use derive_builder::Builder;
use ipaddress::IPAddress;
use ipnet;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use mutal_agreement::*;
use rand::prelude::*;
use rand::Error;
use rand_distr::Distribution;
use rand_distr::WeightedAliasIndex;
use std::char::MAX;
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::process::exit;
use std::rc::Rc;
use std::slice::Iter;
use std::vec;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::Display;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};
use torscaler::parser::descriptor;
use torscaler::parser::meta;
use torscaler::parser::*;

/*For example Exit:
 *                                                          weg * sum(bandwidth_Guard_flagged_relays)
 * P("Selecting Guard-Flagged relay as Exit") = -----------------------------------------------------------------
 *                                             weg * sum_bw_g + wem * sum_bw_m + wee * sum_bw_e + wed * sum_bw_d
 */
#[derive(Debug, Clone)]
pub struct OrAddressNet {
    pub ip: IpNet,
    pub port: u16,
}

#[derive(Debug, Builder, Clone)]
pub struct TorCircuitRelay {
    fingerprint: torscaler::parser::meta::Fingerprint,
    family: Vec<Fingerprint>,
    or_addresses: Vec<torscaler::parser::descriptor::OrAddress>,
    bandwidth: u64,
    flags: Vec<consensus::Flag>,
    /* For easier debugging */
    nickname: String,
    exit_policies: descriptor::DescriptorExitPolicy,
}

impl std::error::Error for TorGeneratorError {}
#[derive(Debug)]
pub enum TorGeneratorError {
    NoRelayFoundForThisPort(u16),
    UnableToSelectGuard,
    UnableToSelectExit(u16),
}

impl fmt::Display for TorGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TorGeneratorError::NoRelayFoundForThisPort(port) => {
                write!(f, "Could not find a suitable relay for port: {}", port)
            }
            TorGeneratorError::UnableToSelectGuard => {
                write!(f, "Could not select a guard relay")
            }
            TorGeneratorError::UnableToSelectExit(port) => {
                write!(f, "Could not select an exit relay for port: {}", port)
            }
        }
    }
}

// https://docs.rs/rand/0.6.5/rand/distributions/struct.WeightedIndex.html
#[derive(Debug, EnumCountMacro, EnumIter, Display, Clone, Copy)]
pub enum RelayType {
    GuardAndExit = 0,
    Exit = 1,
    Guard = 2,
    NotFlagged = 3,
}

#[derive(Debug, EnumCountMacro, EnumIter, Display, Clone, Copy)]
pub enum Position {
    Guard = 0,
    Middle = 1,
    Exit = 2,
}

/* We have one of those for each possible Flag combination:
 * Exit, Guard, Exit+Guard and NotFlagged
 */
pub struct RelayDistribution {
    pub bandwidth_sum: u64,
    pub weights: Vec<u64>,
    pub distr: WeightedAliasIndex<u64>,
    pub relays: Vec<Rc<TorCircuitRelay>>,
}
impl<'a> Default for RelayDistribution {
    fn default() -> RelayDistribution {
        RelayDistribution {
            bandwidth_sum: 0,
            weights: vec![],
            distr: WeightedAliasIndex::new(vec![1]).unwrap(),
            relays: vec![],
        }
    }
}

pub struct CircuitGenerator {
    pub relays: Vec<Rc<TorCircuitRelay>>,
    pub guard_distr: RelayDistribution,
    pub middle_distr: RelayDistribution,
    pub exit_distr: Vec<Option<RelayDistribution>>,
    pub family_agreement: MutalAgreement,
}

pub struct TorCircuit {
    pub guard: Rc<TorCircuitRelay>,
    pub middle: Vec<Rc<TorCircuitRelay>>,
    pub exit: Rc<TorCircuitRelay>,
}

impl<'a> fmt::Display for TorCircuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut line = format!("{}", self.guard.fingerprint);
        line += ", ";
        for middle in &self.middle {
            line += (format!("{}", middle.fingerprint) + ", ").as_str();
        }
        line += format!("{}", self.guard.fingerprint).as_str();
        write!(f, "{}", line)
    }
}

/* There is no real reason for u8 here, asides that I think larger circuits are ridiculus
    TODO OPtions: 2.2.2. User configuration
    "ExitNodes" (strict)
    "EntryNodes" (strict)
    <target>.<servername>.exit
    "HSLayer2Nodes" and "HSLayer3Nodes"
    "Fast" circuits
    All service-side introduction circuits and all rendezvous paths
       should be Stable.

    All connection requests for connections that we think will need to
       stay open a long time require Stable circuits.  Currently, Tor decides
       this by examining the request's target port, and comparing it to a
       list of "long-lived" ports. (Default: 21, 22, 706, 1863, 5050,
       5190, 5222, 5223, 6667, 6697, 8300.)

           - DNS resolves require an exit node whose exit policy is not equivalent
       to "reject *:*".
    All connection requests require an exit node whose exit policy
       supports their target address and port (if known), or which "might
       support it" (if the address isn't known).  See 2.2.1.
     - Rules for Fast? XXXXX

    requirements:
    We do not choose the same router twice for the same path.
     - We do not choose any router in the same family as another in the same
       path. (Two routers are in the same family if each one lists the other
       in the "family" entries of its descriptor.)
     - We do not choose more than one router in a given /16 subnet
       (unless EnforceDistinctSubnets is 0).
     - We don't choose any non-running or non-valid router unless we have
       been configured to do so. By default, we are configured to allow
       non-valid routers in "middle" and "rendezvous" positions.
     - If we're using Guard nodes, the first node must be a Guard (see 5
       below)
     - XXXX Choosing the length

     "Exit" if the router is more useful for building
             general-purpose exit circuits than for relay circuits.  The
             path building algorithm uses this flag; see path-spec.txt

*/
const MAX_SAMPLE_TRYS: u32 = 1000;
struct TorCircuitConstruction<'a> {
    guard: Option<Rc<TorCircuitRelay>>,
    middle: Vec<Rc<TorCircuitRelay>>,
    exit: Option<Rc<TorCircuitRelay>>,
    relays: Vec<Rc<TorCircuitRelay>>,
    hs_subnets: HashSet<String>,
    cg: &'a CircuitGenerator,
}
impl<'a> TorCircuitConstruction<'a> {
    pub fn new(cg: &'a CircuitGenerator) -> Self {
        TorCircuitConstruction {
            guard: None,
            middle: vec![],
            exit: None,
            relays: vec![],
            hs_subnets: HashSet::new(),
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
        for i in 0..MAX_SAMPLE_TRYS {
            if self.check_requirements(&guard_relay) {
                self.update_requirements(&guard_relay);
                self.relays.push(Rc::clone(&guard_relay));
                self.guard = Some(Rc::clone(&guard_relay));
                return Ok(())
            }
            guard_relay = self.sample_guard_relay();
        }
        Err(Box::new(TorGeneratorError::UnableToSelectGuard))
    }

    pub fn add_middle_relay(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut middle_relay = self.sample_middle_relay();
        for i in 0..MAX_SAMPLE_TRYS {
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
        match &self.cg.exit_distr[target_port as usize] {
            Some(distr) => {
                let mut rng = thread_rng();
                let relay_idx = 
                    distr.distr
                    .sample(&mut rng);
                Ok(Rc::clone(
                    &distr.relays[relay_idx],
                ))
            }
            None => Err(Box::new(TorGeneratorError::UnableToSelectExit(target_port)))
        }
        
    }

    pub fn sample_guard_relay(&self) -> Rc<TorCircuitRelay> {
        let mut rng = thread_rng();
        let relay_idx = self.cg.guard_distr.distr.sample(&mut rng);
        Rc::clone(&self.cg.guard_distr.relays[relay_idx])
    }

    pub fn sample_middle_relay(&self) -> Rc<TorCircuitRelay> {
        let mut rng = thread_rng();
        let relay_idx = self.cg.middle_distr.distr.sample(&mut rng);
        Rc::clone(&self.cg.middle_distr.relays[relay_idx])
    }
    pub fn update_requirements(&mut self, relay: &Rc<TorCircuitRelay>) {
        for address in &relay.or_addresses {
            let netAddr = match IpNet::new(address.ip, 16) {
                Ok(addr) => addr,
                Err(e) => {
                    println!("IPNet Error: {}", e);
                    continue;
                }
            };
            self.hs_subnets.insert(netAddr.to_string());
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
            let netAddr = match IpNet::new(address.ip, 16) {
                Ok(addr) => addr,
                Err(e) => {
                    println!("IPNet Error: {}", e);
                    continue;
                }
            };
            if self.hs_subnets.contains(&netAddr.to_string()) {
                //println!("Subnet error: {}", netAddr.to_string());
                return false;
            }
        }
        //println!("success!!!!");
        return true;
    }
}

pub fn build_circuit(
    cg: &CircuitGenerator,
    length: u8,
    target_port: u16,
) -> Result<TorCircuit, Box<dyn std::error::Error>> {
    let mut circ = TorCircuitConstruction::new(cg);
    circ.add_exit_relay(target_port)?;
    circ.add_guard_relay()?;
    for i in 0..(length - 2) {
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

fn determine_relay_type(relay: &TorCircuitRelay) -> RelayType {
    /* There are more performant orders, but this is readable and I rather leave the optimization to the compiler */
    let guard = consensus::Flag::Guard;
    let exit = consensus::Flag::Exit;
    if relay.flags.contains(&guard) && relay.flags.contains(&exit) {
        return RelayType::GuardAndExit;
    } else if relay.flags.contains(&exit) {
        return RelayType::Exit;
    } else if relay.flags.contains(&guard) {
        return RelayType::Guard;
    } else {
        return RelayType::NotFlagged;
    }
}

fn compute_range_from_port(port: &descriptor::ExitPolicyPort) -> std::ops::Range<usize> {
    match port {
        descriptor::ExitPolicyPort::Wildcard => {
            return 0..u16::MAX.into();
        }
        descriptor::ExitPolicyPort::Port(value) => match value {
            descriptor::Range::Single(v) => return *v as usize..(*v + 1) as usize,
            descriptor::Range::Interval(v1, v2) => return *v1 as usize..(*v2 + 1) as usize,
        },
    }
}

fn compute_tor_circuit_relays<'a>(
    consensus: &'a consensus::ConsensusDocument,
    descriptors: Vec<torscaler::parser::descriptor::Descriptor>,
) -> Vec<Rc<TorCircuitRelay>> {
    let mut missingDescriptors = 0;
    let mut buildFailed = 0;
    let mut relays: Vec<Rc<TorCircuitRelay>> = vec![];
    let mut dropped_bandwidth_0 = 0;
    let mut droppped_not_running = 0;

    let mut descriptors: HashMap<Fingerprint, descriptor::Descriptor> = descriptors
        .into_iter()
        .filter(|d| d.digest.is_some())
        .map(|d| {
            (
                d.digest.clone().unwrap(),
                //.ok_or(DocumentCombiningError::DescriptorMissesDigest)?,
                d,
            )
        })
        .collect();

    let mut nicknames_to_fingerprints: HashMap<String, Option<Fingerprint>> = HashMap::new();
    {
        for relay in consensus.relays.iter() {
            let nickname = relay.nickname.clone();
            match nicknames_to_fingerprints.entry(nickname) {
                Entry::Vacant(e) => {
                    e.insert(Some(relay.fingerprint.clone()));
                }
                Entry::Occupied(mut e) => {
                    // if this nickname is already known, remember that it is not unique
                    e.insert(None);
                }
            }
        }
    }

    for consensus_relay in consensus.relays.iter() {
        let result = descriptors.remove(&consensus_relay.digest).ok_or_else(|| {
            DocumentCombiningError::MissingDescriptor {
                digest: consensus_relay.digest.clone(),
            }
        });
        if consensus_relay.bandwidth_weight == 0 {
            /*println!(
                "WARNING: Descriptor: {} has Consensus bandwidth of 0 and is dropped!",
                descriptor.nickname
            );*/
            dropped_bandwidth_0 = dropped_bandwidth_0 + 1;
            continue;
        }

        let flag_running = consensus::Flag::Running;
        if !consensus_relay.flags.contains(&flag_running) {
            droppped_not_running = droppped_not_running + 1;
            continue;
        }
        let descriptor = match result {
            Ok(desc) => desc,
            Error => {
                missingDescriptors += 1;
                continue;
            }
        };

        let mut circuit_relay = TorCircuitRelayBuilder::default();
        circuit_relay.fingerprint(consensus_relay.fingerprint.clone());
        circuit_relay.bandwidth(consensus_relay.bandwidth_weight);

        let known_fingerprints: HashSet<Fingerprint> = consensus
            .relays
            .iter()
            .map(|r| r.fingerprint.clone())
            .collect();

        let filter_family_member = |f: descriptor::FamilyMember| match f {
            descriptor::FamilyMember::Fingerprint(fingerprint) => {
                if known_fingerprints.contains(&fingerprint) {
                    Some(fingerprint)
                } else {
                    None
                }
            }
            descriptor::FamilyMember::Nickname(nickname) => {
                if let Some(entry) = nicknames_to_fingerprints.get(&nickname) {
                    if let Some(fingerprint) = entry {
                        return Some(fingerprint.clone());
                    }
                }
                None
            }
        };
        match descriptor.family_members {
            None => {
                continue;
            }
            Some(family) => {
                circuit_relay.family(
                    family
                        .into_iter()
                        // keep only family members that do exist, and convert them to fingerprints
                        .filter_map(filter_family_member)
                        .collect(),
                );
            }
        };
        circuit_relay.nickname = descriptor.nickname;
        let mut flags = vec![];
        for flag in consensus_relay.flags.iter() {
            flags.push(flag.clone());
        }
        circuit_relay.flags(flags);
        circuit_relay.or_addresses = descriptor.or_addresses;
        circuit_relay.exit_policies = descriptor.exit_policy;

        let relay = match circuit_relay.build() {
            Ok(circ_relay) => circ_relay,
            Err(err) => {
                println!("Error: {}", err.to_string());
                buildFailed += 1;
                continue;
            }
        };

        relays.push(Rc::new(relay));
    }
    println!("Error summary:\n bandwidth 0: {},\n not running: {},\n missing Descriptors: {}\n build failed: {}\n", dropped_bandwidth_0, droppped_not_running, missingDescriptors, buildFailed);
    relays
}

pub fn prepare_distributions(
    relays: &Vec<Rc<TorCircuitRelay>>,
    guard_distr: &mut RelayDistribution,
    middle_distr: &mut RelayDistribution,
    exit_distr: &mut Vec<Option<RelayDistribution>>,
    family_agreement: &mut mutal_agreement::MutalAgreement,
    consensus_weights: &BTreeMap<String, u64>,
) {
    const INIT_PORT_ARRAY: Option<descriptor::ExitPolicyType> = None;
    for relay in relays.iter() {
        let relay_type = determine_relay_type(&relay);

        let relay_fingerprint_str = format!("{}", relay.fingerprint);
        for family_fingerprint in &relay.family {
            let family_fingerprint_str = format!("{}", family_fingerprint);
            family_agreement.agree(&relay_fingerprint_str, &family_fingerprint_str);
        }

        let mut port_array = Box::new([INIT_PORT_ARRAY; u16::MAX as usize]);

        for policy in &relay.exit_policies.rules {
            /* We only consider rules that apply to ALL IP addresses. */
            if policy.address != descriptor::ExitPolicyAddress::Wildcard {
                continue;
            }
            for i in compute_range_from_port(&policy.port) {
                if port_array[i] == None {
                    port_array[i] = Some(policy.ep_type);
                }
            }
        }

        let guard_weight =
            relay.bandwidth * positional_weight(Position::Guard, relay_type, consensus_weights);
        guard_distr.relays.push(Rc::clone(relay));
        guard_distr.weights.push(guard_weight);
        guard_distr.bandwidth_sum += guard_weight;

        let middle_weight =
            relay.bandwidth * positional_weight(Position::Middle, relay_type, consensus_weights);
        middle_distr.relays.push(Rc::clone(relay));
        middle_distr.weights.push(middle_weight);
        middle_distr.bandwidth_sum += middle_weight;

        for port in 0..port_array.len() {
            if port_array[port] == Some(descriptor::ExitPolicyType::Accept) {
                let exit_weight = relay.bandwidth
                    * positional_weight(Position::Exit, relay_type, consensus_weights);
                if let None = exit_distr[port] {
                        exit_distr[port] = Some(RelayDistribution::default());
                }
                let distr = exit_distr[port].as_mut().unwrap();
                distr.relays.push(Rc::clone(relay));
                distr.weights.push(exit_weight);
                distr.bandwidth_sum += exit_weight;
            }
        }
    }
}

fn positional_weight(
    position: Position,
    relay_type: RelayType,
    consensus_weights: &BTreeMap<String, u64>,
) -> u64 {
    match position {
        Position::Guard => match relay_type {
            RelayType::Exit => 0,
            RelayType::Guard => *consensus_weights.get("Wgg").unwrap(),
            RelayType::GuardAndExit => *consensus_weights.get("Wgd").unwrap(),
            RelayType::NotFlagged => *consensus_weights.get("Wgm").unwrap(),
        },
        Position::Middle => match relay_type {
            RelayType::Exit => *consensus_weights.get("Wme").unwrap(),
            RelayType::Guard => *consensus_weights.get("Wmg").unwrap(),
            RelayType::GuardAndExit => *consensus_weights.get("Wmd").unwrap(),
            RelayType::NotFlagged => *consensus_weights.get("Wmm").unwrap(),
        },
        Position::Exit => match relay_type {
            RelayType::Exit => *consensus_weights.get("Wee").unwrap(),
            RelayType::Guard => *consensus_weights.get("Weg").unwrap(),
            RelayType::GuardAndExit => *consensus_weights.get("Wed").unwrap(),
            RelayType::NotFlagged => *consensus_weights.get("Wem").unwrap(),
        },
    }
}
impl<'a> CircuitGenerator {
    pub fn new(
        consensus: &'a consensus::ConsensusDocument,
        descriptors: Vec<torscaler::parser::descriptor::Descriptor>,
    ) -> Self {

        const INIT_EXIT_DISTR: Option<RelayDistribution> = None;

        let mut family_agreement = mutal_agreement::MutalAgreement::new();

        let relays = compute_tor_circuit_relays(consensus, descriptors);
        let mut guard_distr: RelayDistribution = RelayDistribution::default();
        let mut middle_distr: RelayDistribution = RelayDistribution::default();
        let mut exit_distr: Vec<Option<RelayDistribution>> = vec![];
        for port in 0.. u16::MAX {
            exit_distr.push(None);
        }
        prepare_distributions(
            &relays,
            &mut guard_distr,
            &mut middle_distr,
            &mut exit_distr,
            &mut family_agreement,
            &consensus.weights,
        );
        guard_distr.distr = WeightedAliasIndex::new(guard_distr.weights.clone()).unwrap();
        middle_distr.distr = WeightedAliasIndex::new(middle_distr.weights.clone()).unwrap();
        for port_distr in exit_distr.iter_mut() {
            if let Some(distr) = port_distr {
                distr.distr = WeightedAliasIndex::new(distr.weights.clone()).unwrap();
            }
        }
        CircuitGenerator {
            relays,
            exit_distr,
            guard_distr,
            middle_distr,
            family_agreement,
        }
    }
}
