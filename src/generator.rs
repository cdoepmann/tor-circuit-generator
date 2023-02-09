use std::borrow::Borrow;
use std::rc::Rc;

use ipnet::IpNet;

use seeded_rand::{RHashMap, RHashSet};
use tordoc;
use tordoc::Fingerprint;

use crate::containers::{PositionWeights, TorCircuit, TorCircuitRelay};
use crate::distribution::{get_distributions, RelayDistribution};
use crate::error::TorGeneratorError;
use crate::input::{compute_families, compute_tor_circuit_relays};
use crate::mutual_agreement::MutualAgreement;

const MAX_SAMPLE_TRYS: u32 = 1000;
struct TorCircuitConstruction<'a> {
    guard: Option<Rc<TorCircuitRelay>>,
    middle: Vec<Rc<TorCircuitRelay>>,
    exit: Option<Rc<TorCircuitRelay>>,
    relays: Vec<Rc<TorCircuitRelay>>,
    hs_subnets: RHashSet<String>,
    cg: &'a CircuitGenerator,
    need_fast: bool,
    need_stable: bool,
}
impl<'a> TorCircuitConstruction<'a> {
    pub fn new(cg: &'a CircuitGenerator, need_fast: bool, need_stable: bool) -> Self {
        TorCircuitConstruction {
            guard: None,
            middle: vec![],
            exit: None,
            relays: vec![],
            hs_subnets: RHashSet::default(),
            cg: cg,
            need_fast,
            need_stable,
        }
    }

    pub fn add_exit_relay(&mut self, target_port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut exit_relay = self.sample_exit_relay(target_port)?;
        for _ in 0..MAX_SAMPLE_TRYS {
            if self.check_requirements(&exit_relay) {
                self.update_requirements(&exit_relay);
                self.relays.push(Rc::clone(&exit_relay));
                self.exit = Some(Rc::clone(&exit_relay));
                return Ok(());
            }
            exit_relay = self.sample_exit_relay(target_port)?;
        }
        Err(Box::new(TorGeneratorError::UnableToSelectExit(target_port)))
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

    pub fn set_guard_relay(
        &mut self,
        guard_relay: Rc<TorCircuitRelay>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.update_requirements(&guard_relay);
        self.relays.push(Rc::clone(&guard_relay));
        self.guard = Some(Rc::clone(&guard_relay));
        return Ok(());
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
        // check the relay flags, if required
        if self.need_fast && !relay.flags.contains(&tordoc::consensus::Flag::Fast) {
            return false;
        }
        if self.need_stable && !relay.flags.contains(&tordoc::consensus::Flag::Stable) {
            return false;
        }

        // check the family relationship
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

        // check for same /16 prefix
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
        // build a circuit that doesn't require the Fast or Stable flag
        self.build_circuit_with_flags(length, target_port, false, false)
    }

    /// Generate a single new circuit, potentially with constraints on the relays' flags.
    ///
    /// If `need_fast` or `need_stable` is true, then only relays with the respective
    /// relay flag are selected.
    pub fn build_circuit_with_flags(
        &self,
        length: u8,
        target_port: u16,
        need_fast: bool,
        need_stable: bool,
    ) -> Result<TorCircuit, Box<dyn std::error::Error>> {
        self.build_circuit_with_flags_and_guard(length, target_port, None, need_fast, need_stable)
    }

    /// Generate a single new circuit, potentially with constraints on the relays' flags,
    /// and a given guard to use.
    ///
    /// If `need_fast` or `need_stable` is true, then only relays with the respective
    /// relay flag are selected.
    pub fn build_circuit_with_flags_and_guard(
        &self,
        length: u8,
        target_port: u16,
        guard: Option<&Fingerprint>,
        need_fast: bool,
        need_stable: bool,
    ) -> Result<TorCircuit, Box<dyn std::error::Error>> {
        let mut circ = TorCircuitConstruction::new(self, need_fast, need_stable);
        match guard {
            None => {
                circ.add_exit_relay(target_port)?;
                circ.add_guard_relay()?;
            }
            Some(fp) => {
                let guard_relay = self
                    .lookup_relay(fp)
                    .ok_or(TorGeneratorError::UnableToSelectGuard)?;
                circ.set_guard_relay(guard_relay)?;
                circ.add_exit_relay(target_port)?;
            }
        }
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

    /// Sample a new guard, given a `Vec` of fingerprints to avoid
    ///
    /// This is for usage by an external guard set handler.
    pub fn sample_new_guard(
        &self,
        guards: &Vec<impl Borrow<Fingerprint>>,
    ) -> Result<Rc<TorCircuitRelay>, Box<dyn std::error::Error>> {
        'guard_sampling: for _ in 0..=(guards.len() * 3 + 1) {
            // select some random relay
            let relay = self.guard_distr.sample();

            // check if it has to be avoided
            for existing_guard in guards.iter().map(|x| x.borrow()) {
                if existing_guard == &relay.fingerprint {
                    continue 'guard_sampling;
                }
            }

            return Ok(relay);
        }

        Err(Box::new(TorGeneratorError::UnableToSelectGuard))
    }

    /// Gets the number of relays in the consensus, grouped by relay type.
    ///
    /// Returns a tuple: `(guards, middles, exits)`. Note that the sum of these
    /// numbers will likely be greater than the overall number of relays in the
    /// consensus as relays can be part of multiple groups at the same time.
    pub fn num_relays(&self) -> (usize, usize, usize) {
        (
            self.guard_distr.len(),
            self.middle_distr.len(),
            self.exit_distrs.len(),
        )
    }
}
