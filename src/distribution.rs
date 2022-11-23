use std::collections::BTreeMap;
use std::rc::Rc;

use rand::prelude::*;
use rand_distr::Distribution;
use rand_distr::WeightedAliasIndex;

use tordoc::consensus::Flag;
use tordoc::descriptor::{ExitPolicyAddress, ExitPolicyType};

use crate::containers::{Position, RelayType, TorCircuitRelay};
use crate::input::compute_range_from_port;

/// A weighted distribution for fast, weighted sampling from relays.
///
/// We have one of these for each possible Flag combination:
/// Exit, Guard, Exit+Guard and NotFlagged.
pub struct RelayDistribution {
    pub bandwidth_sum: u64,
    // weights: Vec<u64>,
    distr: WeightedAliasIndex<u64>,
    relays: Vec<Rc<TorCircuitRelay>>,
}

impl RelayDistribution {
    /// Samples a relay from the distribution, returning it as an `Rc`.
    pub(crate) fn sample(&self) -> Rc<TorCircuitRelay> {
        let mut rng = thread_rng();
        let relay_idx = self.distr.sample(&mut rng);
        Rc::clone(&self.relays[relay_idx])
    }
}

impl From<RelayDistributionCollector> for RelayDistribution {
    fn from(x: RelayDistributionCollector) -> Self {
        RelayDistribution {
            distr: WeightedAliasIndex::new(x.weights.clone()).unwrap(),
            relays: x.relays,
            // weights: x.weights,
            bandwidth_sum: x.bandwidth_sum,
        }
    }
}

/// A possibly unfinished version of a `RelayDistribution`
struct RelayDistributionCollector {
    bandwidth_sum: u64,
    weights: Vec<u64>,
    relays: Vec<Rc<TorCircuitRelay>>,
}

impl RelayDistributionCollector {
    fn new() -> Self {
        RelayDistributionCollector {
            bandwidth_sum: 0,
            weights: Vec::new(),
            relays: Vec::new(),
        }
    }

    fn push(&mut self, relay: &Rc<TorCircuitRelay>, weight: u64) {
        self.relays.push(Rc::clone(relay));
        self.weights.push(weight);
        self.bandwidth_sum += weight;
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

/// Derive the relay distributions per relay type from a provided list of
/// `TorCircuitRelay`
///
/// This returns a tuple containing three distributions: (guard, middle, exit).
/// Note that the exit "distribution" is in fact a `Vec` of distributions,
/// one for each exit port.
pub fn get_distributions(
    relays: &Vec<Rc<TorCircuitRelay>>,
    consensus_weights: &BTreeMap<String, u64>,
) -> (
    RelayDistribution,
    RelayDistribution,
    Vec<Option<RelayDistribution>>,
) {
    let mut guard_distr = RelayDistributionCollector::new();
    let mut middle_distr = RelayDistributionCollector::new();

    let mut exit_distrs: Vec<_> = (0..=u16::MAX).into_iter().map(|_| None).collect();

    const INIT_PORT_ARRAY: Option<ExitPolicyType> = None;
    for relay in relays.iter() {
        let relay_type = RelayType::from_relay(relay);
        let weight =
            |pos: Position| relay.bandwidth * positional_weight(pos, relay_type, consensus_weights);

        // handle exit distributions

        let mut port_array = Box::new([INIT_PORT_ARRAY; u16::MAX as usize + 1]);

        for policy in &relay.exit_policies.rules {
            /* We only consider rules that apply to ALL IP addresses. */
            if policy.address != ExitPolicyAddress::Wildcard {
                continue;
            }
            for i in compute_range_from_port(&policy.port) {
                if port_array[i].is_none() {
                    port_array[i] = Some(policy.ep_type);
                }
            }
        }

        for port in 1..port_array.len() {
            if let Some(ExitPolicyType::Accept) = port_array[port] {
                exit_distrs[port]
                    .get_or_insert_with(RelayDistributionCollector::new)
                    .push(relay, weight(Position::Exit));
            }
        }

        // Handle guard distribution
        if relay.flags.contains(&Flag::Guard) {
            guard_distr.push(relay, weight(Position::Guard));
        }

        // Handle middle distribution
        middle_distr.push(relay, weight(Position::Middle));
    }

    (
        // Guard
        guard_distr.into(),
        // Middle
        middle_distr.into(),
        // Exit
        exit_distrs
            .into_iter()
            // finalize to RelayDistribution objects
            .map(|o| o.map(|c| c.into()))
            .collect(),
    )
}
