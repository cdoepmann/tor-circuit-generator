use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use rand::prelude::*;
use rand_distr::Distribution;
use rand_distr::WeightedAliasIndex;

use tordoc::consensus::{CondensedExitPolicy, ExitPolicyType, Flag};

use crate::containers::{Position, PositionWeights, RelayType, TorCircuitRelay};

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
    consensus_weights: &PositionWeights,
) -> u64 {
    match position {
        Position::Guard => match relay_type {
            RelayType::Exit => 0,
            RelayType::Guard => consensus_weights.Wgg,
            RelayType::GuardAndExit => consensus_weights.Wgd,
            RelayType::NotFlagged => consensus_weights.Wgm,
        },
        Position::Middle => match relay_type {
            RelayType::Exit => consensus_weights.Wme,
            RelayType::Guard => consensus_weights.Wmg,
            RelayType::GuardAndExit => consensus_weights.Wmd,
            RelayType::NotFlagged => consensus_weights.Wmm,
        },
        Position::Exit => match relay_type {
            RelayType::Exit => consensus_weights.Wee,
            RelayType::Guard => consensus_weights.Weg,
            RelayType::GuardAndExit => consensus_weights.Wed,
            RelayType::NotFlagged => consensus_weights.Wem,
        },
    }
}

/// Derive the relay distributions per relay type from a provided list of
/// `TorCircuitRelay`
///
/// This returns a tuple containing three distributions: (guard, middle, exit).
/// Note that the exit "distribution" is in fact a map of distributions,
/// one for each requested exit port.
pub(crate) fn get_distributions(
    relays: &Vec<Rc<TorCircuitRelay>>,
    consensus_weights: PositionWeights,
    exit_ports: Vec<u16>,
) -> (
    RelayDistribution,
    RelayDistribution,
    HashMap<u16, RelayDistribution>,
) {
    let mut guard_distr = RelayDistributionCollector::new();
    let mut middle_distr = RelayDistributionCollector::new();

    let mut exit_distrs = HashMap::new();

    for relay in relays.iter() {
        let relay_type = RelayType::from_relay(relay);
        let weight = |pos: Position| {
            relay.bandwidth * positional_weight(pos, relay_type, &consensus_weights)
        };

        // handle exit distributions
        match relay.exit_policy {
            CondensedExitPolicy {
                policy_type: ExitPolicyType::Reject,
                ..
            } => {
                // relay doesnt allow any exit port, ignore it
            }
            CondensedExitPolicy {
                policy_type: ExitPolicyType::Accept,
                entries: ref rules,
            } => {
                for rule in rules.iter() {
                    for port in exit_ports.iter() {
                        if rule.contains(*port) {
                            exit_distrs
                                .entry(*port)
                                .or_insert_with(RelayDistributionCollector::new)
                                .push(relay, weight(Position::Exit));
                        }
                    }
                }
            }
        };

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
            .map(|(k, v)| (k, v.into()))
            .collect(),
    )
}
