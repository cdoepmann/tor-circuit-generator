use ipaddress::IPAddress;
use ipnet;
use mutal_agreement::*;
use rand::prelude::*;
use rand::Error;
use rand_distr::Distribution;
use rand_distr::WeightedAliasIndex;
use std::char::MAX;
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

/*For example Exit:
 *                                                          weg * sum(bandwidth_Guard_flagged_relays)
 * P("Selecting Guard-Flagged relay as Exit") = -----------------------------------------------------------------
 *                                             weg * sum_bw_g + wem * sum_bw_m + wee * sum_bw_e + wed * sum_bw_d
 */
#[derive(Debug, Clone)]
pub struct OrAddressNet {
    pub ip: IpAddr,
    pub port: u16,
}
pub struct TorCircuitRelay {
    fingerprint: torscaler::parser::meta::Fingerprint,
    family: Vec<descriptor::FamilyMember>,
    or_addresses: Vec<OrAddressNet>,
    /* Todo: maybe Replaced by flag */
    is_guard: bool,
    is_exit: bool,
    bandwidth_consensus: u128,
    is_running: bool,
    flag: Flag,
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
pub enum Flag {
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

pub struct FlagCategory<'a> {
    pub bandwidth_sum: u128,
    pub weights: Vec<u128>,
    pub distr: WeightedAliasIndex<u128>,
    pub relays: Vec<&'a TorCircuitRelay>,
    pub exit_policy_distr: Vec<Option<WeightedAliasIndex<u128>>>,
    pub exit_policy_nodes: Vec<Vec<&'a TorCircuitRelay>>,
}
impl<'a> Default for FlagCategory<'a> {
    fn default() -> FlagCategory<'a> {
        FlagCategory {
            bandwidth_sum: 0,
            weights: vec![],
            distr: WeightedAliasIndex::new(vec![1]).unwrap(),
            relays: vec![],
            exit_policy_distr: vec![],
            exit_policy_nodes: vec![vec![]; u16::MAX.into()],
        }
    }
}

pub struct CircuitGenerator<'a> {
    pub flag_categories: [FlagCategory<'a>; Flag::COUNT],
    pub exit_weights: [u128; Flag::COUNT],
    pub exit_distr: WeightedAliasIndex<u128>,
    pub guard_weights: [u128; Flag::COUNT],
    pub guard_distr: WeightedAliasIndex<u128>,
    pub middle_weights: [u128; Flag::COUNT],
    pub middle_distr: WeightedAliasIndex<u128>,
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
    input_weights: Vec<u128>,
    flag_categories: &[FlagCategory; Flag::COUNT],
) -> [u128; Flag::COUNT] {
    let mut weights = [0; Flag::COUNT];
    for flag in Flag::iter() {
        let flag_idx = flag as usize;
        weights[flag_idx] = input_weights[flag_idx] * flag_categories[flag_idx].bandwidth_sum;
        /*println!(
            "Weights: {} = input: {} * flag_categories: {} \n flag_idx: {}",
            weights[flag_idx],
            input_weights[flag_idx],
            flag_categories[flag_idx].bandwidth_sum,
            flag_idx
        );*/
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
    distr: &WeightedAliasIndex<u128>,
) -> &'a TorCircuitRelay {
    let mut rng = thread_rng();
    let flag_idx = distr.sample(&mut rng);
    let idx = ps.flag_categories[flag_idx].distr.sample(&mut rng);
    return ps.flag_categories[flag_idx].relays[idx];
}

fn desc2flag(descriptor: &TorCircuitRelay) -> Flag {
    /* There are more performant orders, but this is readable and I rather leave the optimization to the compiler */
    if descriptor.is_guard && descriptor.is_exit {
        return Flag::GuardAndExit;
    } else if descriptor.is_exit {
        return Flag::Exit;
    } else if descriptor.is_guard {
        return Flag::Guard;
    } else {
        return Flag::NotFlagged;
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

fn get_positional_weight(pos: Position, flag: Flag, consensus: &Consensus) -> u128 {
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
) -> Result<rand_distr::WeightedAliasIndex<u128>, Box<dyn std::error::Error>> {
    let mut weights: Vec<u128> = vec![];
    for desc in descriptors {
        let pos_weight = get_positional_weight(Position::Exit, desc2flag(desc), consensus);
        weights.push(desc.bandwidth_consensus * pos_weight);
    }
    Ok(WeightedAliasIndex::new(weights)?)
}

fn compute_bandwidth_distribution(
    descriptors: &Vec<&TorCircuitRelay>,
) -> Result<rand_distr::WeightedAliasIndex<u128>, Box<dyn std::error::Error>> {
    let mut weights: Vec<u128> = vec![];

    for desc in descriptors {
        print!("{} ", desc.bandwidth_consensus);
        weights.push(desc.bandwidth_consensus);
    }
    Ok(WeightedAliasIndex::new(weights)?)
}

impl<'a> CircuitGenerator<'a> {
    pub fn new(consensus: &'a consensus::ConsensusDocument, descriptors: Vec<torscaler::parser::descriptor::Descriptor>) -> Self {
        /* Better rewrite this from scratch 
         * 1. Build our own vector of "circuit-relays" (only the required attributes for circuit generation)
         * 2. Order them by Flag 
         * 3. calculate distributions
         * 4. Profit
         */
 



        const INIT_PORT_ARRAY: Option<descriptor::ExitPolicyType> = None;
        let mut dropped_bandwidth_0 = 0;
        let mut droppped_not_running = 0;

        let mut flag_categories: [FlagCategory; Flag::COUNT] = Default::default();
        for flag in Flag::iter() {
            let flag_idx = flag as usize;
            /* TODO */
            flag_categories[flag_idx] = FlagCategory::default();
        }
        let c_bw = &consensus.weights;
        let mut family_agreement = mutal_agreement::MutalAgreement::new();

        for descriptor in consensus.relays {
            let flag_idx = desc2flag(descriptor) as usize;

            if descriptor.bandwidth_weight == 0 {
                /*println!(
                    "WARNING: Descriptor: {} has Consensus bandwidth of 0 and is dropped!",
                    descriptor.nickname
                );*/
                dropped_bandwidth_0 = dropped_bandwidth_0 + 1;
                continue;
            }

            let flag_running = consensus::Flag::Running;
            if ! descriptor.flags.contains(&flag_running) {
                droppped_not_running = droppped_not_running + 1;
                continue;
            }
            for family in &descriptor.family {
                let mut family_fingerprint;
                if family.starts_with('$') {
                    family_fingerprint = family.chars();
                    family_fingerprint.next();
                    let family_fingerprint_str = family_fingerprint.collect::<String>();
                    family_agreement.agree(&descriptor.fingerprint, &family_fingerprint_str);
                } else {
                    // If it does not start with $ it is probably a nickname
                    println!(
                        "Found nickname: {} in desc: {}",
                        family, descriptor.nickname
                    );
                    // TODO
                    continue;
                }
            }

            flag_categories[flag_idx].relays.push(descriptor);
            flag_categories[flag_idx]
                .weights
                .push(descriptor.bandwidth_consensus);
            flag_categories[flag_idx].bandwidth_sum += descriptor.bandwidth_consensus;
            /*println!(
                "idx: {} bw_sum: {} bw_c: {}",
                flag_idx, flag_categories[flag_idx].bandwidth_sum, descriptor.bandwidth_consensus,
            );*/

            let mut port_array = [INIT_PORT_ARRAY; u16::MAX as usize];

            for policy in &descriptor.exit_policies {
                if policy.address != descriptor::ExitPolicyAddress::Wildcard {
                    continue;
                }

                for i in compute_range_from_port(&policy.port) {
                    if port_array[i] == None {
                        port_array[i] = Some(policy.policy);
                    }
                }
            }
            for index in 0..port_array.len() {
                if port_array[index] == Some(descriptor::ExitPolicyType::Accept) {
                    flag_categories[flag_idx].exit_policy_nodes[index].push(descriptor);
                }
            }
        }

        for flag in Flag::iter() {
            let flag_idx = flag as usize;
            flag_categories[flag_idx].exit_policy_distr = (0..u16::MAX)
                .map(|index| {
                    if flag_categories[flag_idx].exit_policy_nodes[index].is_empty() {
                        None
                    } else {
                        /*println!(
                            "Flag: {} idx: {} size: {} is_empty: {}",
                            flag_idx,
                            index,
                            flag_categories[flag_idx].exit_policy_nodes[index].len(),
                            flag_categories[flag_idx].exit_policy_nodes[index].is_empty()
                        );*/
                        Some(
                            compute_weighted_bandwidth_distribution(
                                &flag_categories[flag_idx].exit_policy_nodes[index],
                                consensus,
                            ) // TOOD error handling in new?!
                            .unwrap(),
                        )
                    }
                })
                .collect();
        }

        let mut exit_consensus_weights = [0; Flag::COUNT];
        exit_consensus_weights[Flag::GuardAndExit as usize] = c_bw.wed;
        exit_consensus_weights[Flag::Guard as usize] = c_bw.weg;
        exit_consensus_weights[Flag::Exit as usize] = c_bw.wee;
        exit_consensus_weights[Flag::NotFlagged as usize] = c_bw.wem;
        let exit_weights = compute_weights(exit_consensus_weights.to_vec(), &flag_categories);
        let mut guard_consensus_weights = [0; Flag::COUNT];
        guard_consensus_weights[Flag::GuardAndExit as usize] = c_bw.wgd;
        guard_consensus_weights[Flag::Guard as usize] = c_bw.wgg;
        guard_consensus_weights[Flag::Exit as usize] = 0;
        guard_consensus_weights[Flag::NotFlagged as usize] = c_bw.wgm;
        let guard_weights = compute_weights(guard_consensus_weights.to_vec(), &flag_categories);
        let mut middle_consensus_weights = [0; Flag::COUNT];
        middle_consensus_weights[Flag::GuardAndExit as usize] = c_bw.wmd;
        middle_consensus_weights[Flag::Guard as usize] = c_bw.wmg;
        middle_consensus_weights[Flag::Exit as usize] = c_bw.wme;
        middle_consensus_weights[Flag::NotFlagged as usize] = c_bw.wmm;
        let middle_weights = compute_weights(middle_consensus_weights.to_vec(), &flag_categories);

        let exit_distr = WeightedAliasIndex::new(exit_weights.to_vec()).unwrap();
        let middle_distr = WeightedAliasIndex::new(guard_weights.to_vec()).unwrap();
        let guard_distr = WeightedAliasIndex::new(middle_weights.to_vec()).unwrap();
        let rand = thread_rng();
        println!("Exit Weights");
        for flag in Flag::iter() {
            let flag_idx = flag as usize;
            println!("{}: {}", flag.to_string(), exit_weights[flag_idx as usize]);
        }
        println!("Middle Weights");
        for flag in Flag::iter() {
            let flag_idx = flag as usize;
            println!("{}: {}", flag, middle_weights[flag_idx]);
        }
        println!("Guard Weights");
        for flag in Flag::iter() {
            let flag_idx = flag as usize;
            println!("{}: {}", flag, guard_weights[flag_idx]);
        }
        println!(
            "Dropped: {} relays because they had 0 bandwidth",
            dropped_bandwidth_0
        );
        println!(
            "Dropped: {} relays because they were not running",
            droppped_not_running
        );
        for flag in Flag::iter() {
            let flag_idx = flag as usize;
            /* TODO */
            flag_categories[flag_idx].distr =
                WeightedAliasIndex::new(flag_categories[flag_idx].weights.clone()).unwrap();
        }

        CircuitGenerator {
            flag_categories,
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

#[test]
fn simple_path_selection_init() {
    let mut consensus = Consensus::new();
    let mut descriptors = vec![];
    assert!(tor_consensus::parse_line_consensus(
        "bandwidth-weights Wbd=0 Wbe=542 Wbg=3431 Wbm=764 Wdb=788 Web=123 Wed=4322 Wee=642 Weg=976 Wem=543 Wgb=53311 Wgd=8999 Wgg=6569 Wgm=333 Wmb=712 Wmd=4343 Wme=99912 Wmg=3431 Wmm=6887",
        String::from(""),
        &mut consensus
    ).is_ok());

    for i in 0..11 {
        descriptors.push(TorCircuitRelay::new(
            i.to_string(),
            ipaddress::IPAddress::parse("123.123.123.123").unwrap(),
            9,
            9,
            0,
        ));
    }

    for i in 0..3 {
        descriptors[i].guard = true;
        descriptors[i].exit = true;
        descriptors[i].bandwidth_consensus = (i as u128) * 37;
    }

    for i in 3..6 {
        descriptors[i].guard = true;
        descriptors[i].bandwidth_consensus = (i as u128) * 37;
    }

    for i in 6..8 {
        descriptors[i].exit = true;
        descriptors[i].bandwidth_consensus = (i as u128) * 37;
    }
    for i in 8..11 {
        descriptors[i].bandwidth_consensus = (i as u128) * 37;
    }

    for descriptor in descriptors {
        consensus
            .descriptors
            .insert(descriptor.nickname.to_string(), descriptor);
    }

    let ps = CircuitGenerator::new(&consensus);

    assert_eq!(
        ps.flag_categories[Flag::GuardAndExit as usize].relays.len(),
        3
    );
    for i in 0..2 {
        assert!(ps.flag_categories[Flag::GuardAndExit as usize]
            .relays
            .iter()
            .find(|x| x.nickname == i.to_string())
            .is_some());
    }

    assert_eq!(ps.flag_categories[Flag::Guard as usize].relays.len(), 3);
    for i in 3..6 {
        assert!(ps.flag_categories[Flag::Guard as usize]
            .relays
            .iter()
            .find(|x| x.nickname == i.to_string())
            .is_some());
    }

    assert_eq!(ps.flag_categories[Flag::Exit as usize].relays.len(), 2);
    for i in 6..8 {
        assert!(ps.flag_categories[Flag::Exit as usize]
            .relays
            .iter()
            .find(|x| x.nickname == i.to_string())
            .is_some());
    }

    assert_eq!(
        ps.flag_categories[Flag::NotFlagged as usize].relays.len(),
        3
    );
    for i in 8..11 {
        assert!(ps.flag_categories[Flag::NotFlagged as usize]
            .relays
            .iter()
            .find(|x| x.nickname == i.to_string())
            .is_some());
    }

    /*Wed=4322 Wee=642 Weg=976 Wem=543 */
    assert_eq!(ps.exit_weights[Flag::GuardAndExit as usize], 4322 * 111);
    assert_eq!(ps.exit_weights[Flag::Guard as usize], 976 * 444);
    assert_eq!(ps.exit_weights[Flag::Exit as usize], 642 * 481);
    assert_eq!(ps.exit_weights[Flag::NotFlagged as usize], 543 * 999);
}
