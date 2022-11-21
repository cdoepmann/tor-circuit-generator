use std::collections::BTreeMap;
use std::rc::Rc;

use rand_distr::WeightedAliasIndex;

use torscaler::parser::consensus::Flag;
use torscaler::parser::descriptor;

use crate::bench;
use crate::containers::{Position, RelayType, TorCircuitRelay};
use crate::input::compute_range_from_port;
use crate::mutual_agreement;

/// A weighted distribution for fast, weighted sampling from relays.
///
/// We have one of these for each possible Flag combination:
/// Exit, Guard, Exit+Guard and NotFlagged.
pub struct RelayDistribution {
    pub bandwidth_sum: u64,
    pub weights: Vec<u64>,
    pub distr: WeightedAliasIndex<u64>,
    pub relays: Vec<Rc<TorCircuitRelay>>,
}

impl<'a> Default for RelayDistribution {
    /// Construct an empty distribution
    fn default() -> RelayDistribution {
        RelayDistribution {
            bandwidth_sum: 0,
            weights: vec![],
            distr: WeightedAliasIndex::new(vec![1]).unwrap(),
            relays: vec![],
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

pub fn prepare_distributions(
    relays: &Vec<Rc<TorCircuitRelay>>,
    guard_distr: &mut RelayDistribution,
    middle_distr: &mut RelayDistribution,
    exit_distr: &mut Vec<Option<RelayDistribution>>,
    family_agreement: &mut mutual_agreement::MutualAgreement,
    consensus_weights: &BTreeMap<String, u64>,
) {
    println!("\t Prepare Distributions:");
    const INIT_PORT_ARRAY: Option<descriptor::ExitPolicyType> = None;
    println!("\t {} x ", relays.len());
    let mut first = true;
    let mut bench = bench::Bench::new();
    for relay in relays.iter() {
        bench.measure("\t\t Determine Relay type", bench::BENCH_ENABLED && first);
        let relay_type = RelayType::from_relay(&relay);
        let relay_fingerprint_str = format!("{}", relay.fingerprint);
        bench.measure("\t\t Fingerprint", bench::BENCH_ENABLED && first);
        for family_fingerprint in &relay.family {
            let family_fingerprint_str = format!("{}", family_fingerprint);
            family_agreement.agree(&relay_fingerprint_str, &family_fingerprint_str);
        }
        bench.measure(
            "\t\t Position Exit Calculations",
            bench::BENCH_ENABLED && first,
        );
        let mut port_array = Box::new([INIT_PORT_ARRAY; u16::MAX as usize + 1]);

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

        for port in 1..port_array.len() {
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
        bench.measure("\t\t Position Guard/Middle", bench::BENCH_ENABLED && first);
        if relay.flags.contains(&Flag::Guard) {
            let guard_weight =
                relay.bandwidth * positional_weight(Position::Guard, relay_type, consensus_weights);
            guard_distr.relays.push(Rc::clone(relay));
            guard_distr.weights.push(guard_weight);
            guard_distr.bandwidth_sum += guard_weight;
        }
        let middle_weight =
            relay.bandwidth * positional_weight(Position::Middle, relay_type, consensus_weights);
        middle_distr.relays.push(Rc::clone(relay));
        middle_distr.weights.push(middle_weight);
        middle_distr.bandwidth_sum += middle_weight;
        bench.measure("", bench::BENCH_ENABLED && first);
        first = false;
    }
}
