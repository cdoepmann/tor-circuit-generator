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
use std::slice::Iter;
use std::vec;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::Display;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};
use torscaler::parser::descriptor;
use torscaler::parser::meta;
use torscaler::parser::*;
use std::rc::Rc;

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
    or_addresses: Vec<OrAddressNet>,
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
    UnableToSelectGuard(u16),
    UnableToSelectExit(u16),
}

impl fmt::Display for TorGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TorGeneratorError::NoRelayFoundForThisPort(port) => {
                write!(f, "Could not find a suitable Relay for port {}", port)
            }
            TorGeneratorError::UnableToSelectGuard(port) => {
                write!(f, "Could not select a guard relay for port: {}", port)
            }
            TorGeneratorError::UnableToSelectExit(port) => {
                write!(f, "Could not select an exit relay for port: {}", port)
            }
        }
    }
}

// https://docs.rs/rand/0.6.5/rand/distributions/struct.WeightedIndex.html
#[derive(Debug, EnumCountMacro, EnumIter, Display, Clone, Copy)]
pub enum PossiblePosition {
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
pub struct PositionalDistribution {
    pub bandwidth_sum: u64,
    pub weights: Vec<u64>,
    pub distr: WeightedAliasIndex<u64>,
    pub relays: Vec<Rc<TorCircuitRelay>>,
    pub exit_policy_distr: Vec<Option<WeightedAliasIndex<u64>>>,
    pub exit_policy_nodes: Vec<Vec<Rc<TorCircuitRelay>>>,
}
impl<'a> Default for PositionalDistribution {
    fn default() -> PositionalDistribution {
        PositionalDistribution {
            bandwidth_sum: 0,
            weights: vec![],
            distr: WeightedAliasIndex::new(vec![1]).unwrap(),
            relays: vec![],
            exit_policy_distr: vec![],
            exit_policy_nodes: vec![vec![]; u16::MAX.into()],
        }
    }
}

pub struct CircuitGenerator {
    pub relays: Vec<Rc<TorCircuitRelay>>,
    pub positional_distributions: [PositionalDistribution; PossiblePosition::COUNT],
    pub exit_weights: [u64; PossiblePosition::COUNT],
    pub exit_distr: WeightedAliasIndex<u64>,
    pub guard_weights: [u64; PossiblePosition::COUNT],
    pub guard_distr: WeightedAliasIndex<u64>,
    pub middle_weights: [u64; PossiblePosition::COUNT],
    pub middle_distr: WeightedAliasIndex<u64>,
    pub family_agreement: MutalAgreement,
}

pub struct TorCircuit<'a> {
    pub guard: &'a TorCircuitRelay,
    pub middle: Vec<&'a TorCircuitRelay>,
    pub exit: &'a TorCircuitRelay,
}

impl<'a> fmt::Display for TorCircuit<'a> {
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

fn compute_weights<'a>(
    input_weights: Vec<u64>,
    positional_distributions: &[PositionalDistribution; PossiblePosition::COUNT],
) -> [u64; PossiblePosition::COUNT] {
    let mut weights = [0; PossiblePosition::COUNT];
    println!("Compute weights!");
    for possible_position in PossiblePosition::iter() {
        let position_idx = possible_position as usize;
        println!("Idx: {} input weight: {} bandwidth_sum: {}", position_idx, input_weights[position_idx], positional_distributions[position_idx].bandwidth_sum );
        weights[position_idx] =
            input_weights[position_idx] * positional_distributions[position_idx].bandwidth_sum;
    }
    weights
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
struct TorCircuitConstruction<'a> {
    guard: Option<&'a TorCircuitRelay>,
    middle: Vec<&'a TorCircuitRelay>,
    exit: Option<&'a TorCircuitRelay>,
    relays: Vec<&'a TorCircuitRelay>,
    hs_subnets: HashSet<String>,
}
impl<'a> TorCircuitConstruction<'a> {
    pub fn new() -> Self {
        TorCircuitConstruction {
            guard: None,
            middle: vec![],
            exit: None,
            relays: vec![],
            hs_subnets: HashSet::new(),
        }
    }
}
/*
fn circuit_check_requirements(
    req: &mut TorCircuitConstruction,
    relay: &TorCircuitRelay,
    ps: &CircuitGenerator,
) -> bool {
    for circ_relay in &req.relays {
        if ps
            .family_agreement
            .agreement_exists(&circ_relay.fingerprint, &relay.fingerprint)
        {
            /*println!(
                "Family requirements failed for: {} and {}",
                circ_relay.nickname, relay.nickname
            );*/
            return false;
        }
    }
    for address in &relay.or_addresses {
        address.ip.change_prefix(16);
        if req.hs_subnets.contains(&address.ip.network().to_string()) {
            return false;
        }
    }
    for address in &relay.or_addresses {
        address.ip.change_prefix(16);
        req.hs_subnets.insert(address.ip.network().to_string());
    }
    return true;
}
*/

/*
pub fn build_circuit<'a>(
    ps: &'a CircuitGenerator<'a>,
    length: u8,
    target_port: u16,
) -> Result<TorCircuit<'a>, Box<dyn std::error::Error>> {
    let mut circ = TorCircuitConstruction::new();
    circ.exit = Some(sample_exit_relay(ps, target_port)?);
    circ.relays.push(circ.exit.unwrap());
    let mut guard = sample_guard_relay(ps);
    loop {
        if circuit_check_requirements(&mut circ, guard, ps) {
            break;
        }
        guard = sample_guard_relay(ps);
    }
    circ.guard = Some(guard);

    let mut current_middle_relay;
    for i in 0..length - 2 {
        loop {
            current_middle_relay = sample_middle_relay(ps);
            if circuit_check_requirements(&mut circ, current_middle_relay, ps) {
                break;
            }
        }
        circ.middle.push(current_middle_relay);
    }
    Ok(TorCircuit {
        guard: circ
            .guard
            .ok_or(TorGeneratorError::UnableToSelectGuard(target_port))?,
        middle: circ.middle,
        exit: circ
            .exit
            .ok_or(TorGeneratorError::UnableToSelectExit(target_port))?,
    })
}
*/
/*
fn sample_middle_relay<'a>(ps: &CircuitGenerator<'a>) -> &'a TorCircuitRelay {
    return sample_relay(ps, &ps.middle_distr);
}

fn sample_guard_relay<'a>(ps: &CircuitGenerator<'a>) -> &'a TorCircuitRelay {
    /*TODO check if relay is valid -> , we are configured to allow
    non-valid routers in "middle" and "rendezvous" positions.

    guess if have to ensure this by checking and resampling if necessary,
    due to the two layered sample approach, adjusting the distributions is not possible
    */
    return sample_relay(ps, &ps.guard_distr);
}

fn sample_exit_relay<'a>(
    ps: &'a CircuitGenerator,
    target_port: u16,
) -> Result<&'a TorCircuitRelay, Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    /* TODO:
    grr, guess this does not work as intended
    Guess for the exit relays I also have to sample the flag_typ for each port,
    otherwise we will get a different distribution or wont be able to sample even if its possible.
    Consider general distr 0, 0.4, 0.4. 0.2
    but for port 443 we have #desc: 0, 2,2,43
    */

    /*TODO check if relay is valid -> , we are configured to allow
    non-valid routers in "middle" and "rendezvous" positions.

    guess if have to ensure this by checking and resampling if necessary,
    due to the two layered sample approach, adjusting the distributions is not possible
    */
    let flag_idx = ps.exit_distr.sample(&mut rng);
    // TODO const exit_usize: usize = Flag::Exit as usize;
    // TODO const guard_and_exit_usize: usize = Flag::GuardAndExit as usize;
    match &ps.flag_categories[flag_idx].exit_policy_distr[target_port as usize] {
        Some(distr) => Ok(
            ps.flag_categories[flag_idx].exit_policy_nodes[target_port as usize]
                [distr.sample(&mut rng)],
        ),
        None => Err(Box::new(TorGeneratorError::NoRelayFoundForThisPort(
            target_port,
        ))),
    }
}
fn sample_relay<'a>(
    ps: &CircuitGenerator<'a>,
    distr: &WeightedAliasIndex<u64>,
) -> &'a TorCircuitRelay {
    let mut rng = thread_rng();
    let flag_idx = distr.sample(&mut rng);
    let idx = ps.flag_categories[flag_idx].distr.sample(&mut rng);
    return ps.flag_categories[flag_idx].relays[idx];
}
*/
fn determineFlag(relay: &TorCircuitRelay) -> PossiblePosition {
    /* There are more performant orders, but this is readable and I rather leave the optimization to the compiler */
    let guard = consensus::Flag::Guard;
    let exit = consensus::Flag::Exit;
    if relay.flags.contains(&guard) && relay.flags.contains(&exit) {
        return PossiblePosition::GuardAndExit;
    } else if relay.flags.contains(&exit) {
        return PossiblePosition::Exit;
    } else if relay.flags.contains(&guard) {
        return PossiblePosition::Guard;
    } else {
        return PossiblePosition::NotFlagged;
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
/*
fn get_positional_weight(pos: Position, flag: Flag, consensus: &Consensus) -> u64 {
    match pos {
        Position::Guard => match flag {
            Flag::GuardAndExit => consensus.meta.bandwidth.wgd,
            Flag::Exit => panic!("Weight \"Exit in Guardposition\" (wbe) is not defined!"),
            Flag::Guard => consensus.meta.bandwidth.wgg,
            Flag::NotFlagged => consensus.meta.bandwidth.wgm,
        },
        Position::Middle => match flag {
            Flag::GuardAndExit => consensus.meta.bandwidth.wmd,
            Flag::Exit => consensus.meta.bandwidth.wme,
            Flag::Guard => consensus.meta.bandwidth.wmg,
            Flag::NotFlagged => consensus.meta.bandwidth.wmm,
        },
        Position::Exit => match flag {
            Flag::GuardAndExit => consensus.meta.bandwidth.wed,
            Flag::Exit => consensus.meta.bandwidth.wee,
            Flag::Guard => consensus.meta.bandwidth.weg,
            Flag::NotFlagged => consensus.meta.bandwidth.wem,
        },
    }
}

fn compute_weighted_bandwidth_distribution(
    descriptors: &Vec<&TorCircuitRelay>,
    consensus: &Consensus,
) -> Result<rand_distr::WeightedAliasIndex<u64>, Box<dyn std::error::Error>> {
    let mut weights: Vec<u64> = vec![];
    for desc in descriptors {
        let pos_weight = get_positional_weight(Position::Exit, desc2flag(desc), consensus);
        weights.push(desc.bandwidth_consensus * pos_weight);
    }
    Ok(WeightedAliasIndex::new(weights)?)
}

fn compute_bandwidth_distribution(
    descriptors: &Vec<&TorCircuitRelay>,
) -> Result<rand_distr::WeightedAliasIndex<u64>, Box<dyn std::error::Error>> {
    let mut weights: Vec<u64> = vec![];

    for desc in descriptors {
        print!("{} ", desc.bandwidth_consensus);
        weights.push(desc.bandwidth_consensus);
    }
    Ok(WeightedAliasIndex::new(weights)?)
}

*/
fn compute_tor_circuit_relays<'a>(
    consensus: &'a consensus::ConsensusDocument,
    descriptors: Vec<torscaler::parser::descriptor::Descriptor>,
) -> Vec<Rc<TorCircuitRelay>> {
    let mut missingDescriptors = 0;
    let mut buildFailed = 0;
    let mut relays: Vec<Rc<TorCircuitRelay>> = vec![];
    let mut dropped_bandwidth_0 = 0;
    let mut droppped_not_running = 0;
    let c_bw = &consensus.weights;
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
        /* TODO!!! */
        circuit_relay.or_addresses(vec![]);
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
fn compute_tor_positional_distributions<'a>(
    relays: & Vec<Rc<TorCircuitRelay>>, 
    positional_distributions: &mut [PositionalDistribution; 4],
    family_agreement: &mut MutalAgreement,
) {
    const INIT_PORT_ARRAY: Option<descriptor::ExitPolicyType> = None;
    for possible_position in PossiblePosition::iter() {
        positional_distributions[possible_position as usize] = PositionalDistribution::default();
    }
    for relay in relays.iter() {
        let position_idx = determineFlag(&relay) as usize;

        let relay_fingerprint_str = match String::from_utf8(relay.fingerprint.blob.clone()) {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {} parsing fingerprint of relay: {}",e, relay.nickname);
                continue;
            }
        };
        for family_fingerprint in &relay.family {
            let family_fingerprint_str = match String::from_utf8(family_fingerprint.blob.clone()) {
                Ok(v) => v,
                Err(e) => {
                    println!("Error parsing fingerprint of relay: {}", relay.nickname);
                    continue;
                }
            };
            family_agreement.agree(&relay_fingerprint_str, &family_fingerprint_str);
        }
        positional_distributions[position_idx].relays.push(Rc::clone(relay));
        println!("Relay Bandwidth: {}", relay.bandwidth);
        positional_distributions[position_idx]
            .weights
            .push(relay.bandwidth);
        positional_distributions[position_idx].bandwidth_sum += relay.bandwidth;
        /*println!(
            "idx: {} bw_sum: {} bw_c: {}",
            flag_idx, positional_distributions[flag_idx].bandwidth_sum, descriptor.bandwidth_consensus,
        );*/

        let mut port_array = [INIT_PORT_ARRAY; u16::MAX as usize];

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
        for index in 0..port_array.len() {
            if port_array[index] == Some(descriptor::ExitPolicyType::Accept) {
                positional_distributions[position_idx].exit_policy_nodes[index].push(Rc::clone(relay));
            }
        }
    }
}
fn init_consenus_weights(
    guard: &mut [u64; PossiblePosition::COUNT],
    middle: &mut [u64; PossiblePosition::COUNT],
    exit: &mut [u64; PossiblePosition::COUNT],
    c_bw: &BTreeMap<String, u64>,
) {
    println!("Map contains:");
    for key in c_bw.keys() {
        println!("Key: {} value: {}", key, c_bw.get(key).unwrap().to_string());
    }
    guard[PossiblePosition::GuardAndExit as usize] = *c_bw.get("Wgd").unwrap();
    guard[PossiblePosition::Guard as usize] = *c_bw.get("Wgg").unwrap();
    guard[PossiblePosition::Exit as usize] = 0;
    guard[PossiblePosition::NotFlagged as usize] = *c_bw.get("Wgm").unwrap();
    middle[PossiblePosition::GuardAndExit as usize] = *c_bw.get("Wmd").unwrap();
    middle[PossiblePosition::Guard as usize] = *c_bw.get("Wmg").unwrap();
    middle[PossiblePosition::Exit as usize] = *c_bw.get("Wme").unwrap();
    middle[PossiblePosition::NotFlagged as usize] = *c_bw.get("Wmm").unwrap();
    exit[PossiblePosition::GuardAndExit as usize] = *c_bw.get("Wed").unwrap();
    exit[PossiblePosition::Guard as usize] = *c_bw.get("Weg").unwrap();
    exit[PossiblePosition::Exit as usize] = *c_bw.get("Wee").unwrap();
    exit[PossiblePosition::NotFlagged as usize] = *c_bw.get("Wem").unwrap();
}
impl<'a> CircuitGenerator {
    pub fn new(
        consensus: &'a consensus::ConsensusDocument,
        descriptors: Vec<torscaler::parser::descriptor::Descriptor>,
    ) -> Self {
        let mut positional_distributions: [PositionalDistribution; PossiblePosition::COUNT] =
            Default::default();
        let mut family_agreement = mutal_agreement::MutalAgreement::new();
        let relays = compute_tor_circuit_relays(
            consensus,
            descriptors,
        );
        compute_tor_positional_distributions(
            &relays,
            &mut positional_distributions,
            &mut family_agreement,
        );

        let mut guard_consensus_weights = [0; PossiblePosition::COUNT];
        let mut middle_consensus_weights = [0; PossiblePosition::COUNT];
        let mut exit_consensus_weights = [0; PossiblePosition::COUNT];
        init_consenus_weights(
            &mut guard_consensus_weights,
            &mut middle_consensus_weights,
            &mut exit_consensus_weights,
            &consensus.weights,
        );
        let guard_weights =
            compute_weights(guard_consensus_weights.to_vec(), &positional_distributions);
        let middle_weights =
            compute_weights(middle_consensus_weights.to_vec(), &positional_distributions);
        let exit_weights =
            compute_weights(exit_consensus_weights.to_vec(), &positional_distributions);
        let exit_distr = WeightedAliasIndex::new(exit_weights.to_vec()).unwrap();
        let middle_distr = WeightedAliasIndex::new(guard_weights.to_vec()).unwrap();
        let guard_distr = WeightedAliasIndex::new(middle_weights.to_vec()).unwrap();
        let rand = thread_rng();
        for possible_position in PossiblePosition::iter() {
            let position_idx = possible_position as usize;
            positional_distributions[position_idx].distr =
                WeightedAliasIndex::new(positional_distributions[position_idx].weights.clone())
                    .unwrap();
        }

        CircuitGenerator {
            relays,
            positional_distributions,
            exit_weights,
            exit_distr,
            guard_weights,
            guard_distr,
            middle_weights,
            middle_distr,
            family_agreement,
        }
    }
}
