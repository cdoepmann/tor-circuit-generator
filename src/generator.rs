use std::rc::Rc;

use ipnet::IpNet;

use tordoc;
use tordoc::Fingerprint;

use crate::containers::{PositionWeights, TorCircuit, TorCircuitRelay};
use crate::distribution::{get_distributions, RelayDistribution};
use crate::error::TorGeneratorError;
use crate::input::{compute_families, compute_tor_circuit_relays};
use crate::mutual_agreement::MutualAgreement;
use crate::{RHashMap, RHashSet};

const MAX_SAMPLE_TRYS: u32 = 1000;
struct TorCircuitConstruction<'a> {
    guard: Option<Rc<TorCircuitRelay>>,
    middle: Vec<Rc<TorCircuitRelay>>,
    exit: Option<Rc<TorCircuitRelay>>,
    relays: Vec<Rc<TorCircuitRelay>>,
    hs_subnets: RHashSet<String>,
    cg: &'a CircuitGenerator,
}
impl<'a> TorCircuitConstruction<'a> {
    pub fn new(cg: &'a CircuitGenerator) -> Self {
        TorCircuitConstruction {
            guard: None,
            middle: vec![],
            exit: None,
            relays: vec![],
            hs_subnets: RHashSet::default(),
            cg: cg,
        }
    }

    pub fn add_exit_relay(&mut self, target_port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let exit_relay = self.sample_exit_relay(target_port)?;
        self.update_requirements(&exit_relay);
        self.relays.push(Rc::clone(&exit_relay));
        self.exit = Some(Rc::clone(&exit_relay));
        Ok(())
    }
    pub fn add_guard_relay(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut guard_relay = self.sample_guard_relay();
        for _ in 0..MAX_SAMPLE_TRYS {
            if self.check_requirements(&guard_relay) {
                self.update_requirements(&guard_relay);
                self.relays.push(Rc::clone(&guard_relay));
                self.guard = Some(Rc::clone(&guard_relay));
                return Ok(());
            }
            guard_relay = self.sample_guard_relay();
        }
        Err(Box::new(TorGeneratorError::UnableToSelectGuard))
    }

    pub fn add_middle_relay(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut middle_relay = self.sample_middle_relay();
        for _ in 0..MAX_SAMPLE_TRYS {
            if self.check_requirements(&middle_relay) {
                self.update_requirements(&middle_relay);
                self.relays.push(Rc::clone(&middle_relay));
                self.middle.push(Rc::clone(&middle_relay));
                return Ok(());
            }
            middle_relay = self.sample_middle_relay();
        }
        Err(Box::new(TorGeneratorError::UnableToSelectGuard))
    }

    fn get_exit_distr(
        &self,
        target_port: u16,
    ) -> Result<&RelayDistribution, Box<dyn std::error::Error>> {
        self.cg
            .exit_distrs
            .get(&target_port)
            .ok_or(Box::new(TorGeneratorError::UnableToSelectExit(target_port)))
    }

    pub fn sample_exit_relay(
        &self,
        target_port: u16,
    ) -> Result<Rc<TorCircuitRelay>, Box<dyn std::error::Error>> {
        /*
        TODO!!!!: 6x
         * For the exit relays I also have to sample the flag_typ for each port,
         * otherwise we will get a different distribution or wont be able to sample even if its possible.
         * Consider general distr 0, 0.4, 0.4. 0.2
         * but for port 443 we have #desc: 0, 2,2,43
         *
         * Sorry for the indices madness, but this is the way sampling works ¯\_(ツ)_/¯
         *
         * We know we want to sample an exit relay, but to not from which relay type:
         * So we sample the type in the first step:
         * exit, guardandExit, guard or Notflagged
         *
         * After that we check if we have a valid port
         */
        /*
        TODO:
             check if relay is valid -> , we are configured to allow
             non-valid routers in "middle" and "rendezvous" positions.
            guess if have to ensure this by checking and resampling if necessary,
            due to the two layered sample approach, adjusting the distributions is not possible
        */
        Ok(self.get_exit_distr(target_port)?.sample())
    }

    pub fn sample_guard_relay(&self) -> Rc<TorCircuitRelay> {
        self.cg.guard_distr.sample()
    }

    pub fn sample_middle_relay(&self) -> Rc<TorCircuitRelay> {
        self.cg.middle_distr.sample()
    }
    pub fn update_requirements(&mut self, relay: &Rc<TorCircuitRelay>) {
        for address in &relay.or_addresses {
            let net_addr = match IpNet::new(address.ip, 16) {
                Ok(addr) => addr,
                Err(e) => {
                    println!("IPNet Error: {}", e);
                    continue;
                }
            };
            self.hs_subnets.insert(net_addr.to_string());
        }
    }
    pub fn check_requirements(&self, relay: &Rc<TorCircuitRelay>) -> bool {
        for circ_relay in self.relays.iter() {
            let circ_relay_fingerprint_str = format!("{}", circ_relay.fingerprint);
            let relay_fingerprint_str = format!("{}", relay.fingerprint);
            if self.cg.family_agreement.agreement_exists(
                circ_relay_fingerprint_str.as_str(),
                relay_fingerprint_str.as_str(),
            ) {
                /*println!(
                    "Family requirements failed for: {} and {}",
                    circ_relay.nickname, relay.nickname
                );*/
                return false;
            }
        }
        for address in &relay.or_addresses {
            /* This is the prefix we want to consider for Tor circuits */
            let net_addr = match IpNet::new(address.ip, 16) {
                Ok(addr) => addr,
                Err(e) => {
                    println!("IPNet Error: {}", e);
                    continue;
                }
            };
            if self.hs_subnets.contains(&net_addr.to_string()) {
                //println!("Subnet error: {}", netAddr.to_string());
                return false;
            }
        }
        //println!("success!!!!");
        return true;
    }
}

pub struct CircuitGenerator {
    pub relays: RHashMap<Fingerprint, Rc<TorCircuitRelay>>,
    pub guard_distr: RelayDistribution,
    pub middle_distr: RelayDistribution,
    pub exit_distrs: RHashMap<u16, RelayDistribution>,
    pub family_agreement: MutualAgreement,
}

impl<'a> CircuitGenerator {
    /// Construct a new circuit generator from Tor documents.
    ///
    /// This does the heavy lifting, building the distribution indices etc.
    pub fn new(
        consensus: &'a tordoc::Consensus,
        descriptors: Vec<tordoc::Descriptor>,
        exit_ports: Vec<u16>,
    ) -> Self {
        let relays = compute_tor_circuit_relays(consensus, descriptors);
        let family_agreement = compute_families(&relays);

        let (guard_distr, middle_distr, exit_distrs) = get_distributions(
            &relays,
            PositionWeights::from_consensus(&consensus),
            exit_ports,
        );

        CircuitGenerator {
            relays: relays
                .into_iter()
                .map(|x| (x.fingerprint.clone(), x))
                .collect(),
            exit_distrs,
            guard_distr,
            middle_distr,
            family_agreement,
        }
    }

    /// Generate a single new circuit.
    pub fn build_circuit(
        &self,
        length: u8,
        target_port: u16,
    ) -> Result<TorCircuit, Box<dyn std::error::Error>> {
        let mut circ = TorCircuitConstruction::new(self);
        circ.add_exit_relay(target_port)?;
        circ.add_guard_relay()?;
        for _ in 0..(length - 2) {
            circ.add_middle_relay()?;
        }

        // Move into circ.build_circuit() -> TorCircuit
        Ok(TorCircuit {
            guard: circ.guard.ok_or(TorGeneratorError::UnableToSelectGuard)?,
            middle: circ.middle,
            exit: circ
                .exit
                .ok_or(TorGeneratorError::UnableToSelectExit(target_port))?,
        })
    }

    /// Given a fingerprint, get the stored relay, if present
    pub fn lookup_relay(&self, fingerprint: &Fingerprint) -> Option<Rc<TorCircuitRelay>> {
        self.relays.get(fingerprint).map(|x| x.clone())
    }
}
