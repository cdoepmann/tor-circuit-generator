use std::sync::Arc;

use rand_distr::Distribution;
use rand_distr::WeightedAliasIndex;

use seeded_rand::{get_rng, RHashMap};
use tordoc::consensus::{CondensedExitPolicy, ExitPolicyType, Flag};

use crate::containers::{Position, PositionWeights, RelayType, TorCircuitRelay};

/// A weighted distribution for fast, weighted sampling from relays.
///
/// We have one of these for each possible Flag combination:
/// Exit, Guard, Exit+Guard and NotFlagged.
pub struct RelayDistribution {
    pub bandwidth_sum: u64,
    distr: WeightedAliasIndex<u64>,
    relays: Vec<Arc<TorCircuitRelay>>,
}

impl RelayDistribution {
    /// Samples a relay from the distribution, returning it as an `Arc`.
    pub(crate) fn sample(&self) -> Arc<TorCircuitRelay> {
        let mut rng = get_rng();
        let relay_idx = self.distr.sample(&mut rng);
        Arc::clone(&self.relays[relay_idx])
    }

    /// Get the number of relays in this distribution
    pub(crate) fn len(&self) -> usize {
        self.relays.len()
    }
}

impl From<AbstractRelayDistributionCollector> for RelayDistribution {
    fn from(x: AbstractRelayDistributionCollector) -> Self {
        RelayDistribution {
            distr: WeightedAliasIndex::new(x.weights.clone()).unwrap(),
            relays: x.relays,
            // weights: x.weights,
            bandwidth_sum: x.bandwidth_sum,
        }
    }
}

trait AbstractRelayDistributionFilteredPush {
    fn filter(&self, relay: &Arc<TorCircuitRelay>) -> bool;
    fn push_unfiltered(&mut self, relay: &Arc<TorCircuitRelay>);

    fn filtered_push(&mut self, relay: &Arc<TorCircuitRelay>) {
        if !self.filter(relay) {
            return;
        }
        self.push_unfiltered(relay);
    }
}

struct GuardDistributionCollector {
    collector: AbstractRelayDistributionCollector,
}

impl GuardDistributionCollector {
    fn new(consensus_weights: &PositionWeights) -> GuardDistributionCollector {
        GuardDistributionCollector {
            collector: AbstractRelayDistributionCollector::new(Position::Guard, consensus_weights),
        }
    }
}

impl AbstractRelayDistributionFilteredPush for GuardDistributionCollector {
    fn filter(&self, relay: &Arc<TorCircuitRelay>) -> bool {
        relay.flags.contains(&Flag::Guard)
            && relay.flags.contains(&Flag::Valid)
            && relay.flags.contains(&Flag::Running)
    }

    fn push_unfiltered(&mut self, relay: &Arc<TorCircuitRelay>) {
        self.collector.push(relay);
    }
}

struct MiddleDistributionCollector {
    collector: AbstractRelayDistributionCollector,
}

impl MiddleDistributionCollector {
    fn new(consensus_weights: &PositionWeights) -> MiddleDistributionCollector {
        MiddleDistributionCollector {
            collector: AbstractRelayDistributionCollector::new(Position::Middle, consensus_weights),
        }
    }
}

impl AbstractRelayDistributionFilteredPush for MiddleDistributionCollector {
    fn filter(&self, relay: &Arc<TorCircuitRelay>) -> bool {
        relay.flags.contains(&Flag::Running)
    }

    fn push_unfiltered(&mut self, relay: &Arc<TorCircuitRelay>) {
        self.collector.push(relay);
    }
}

struct ExitDistributionCollector {
    collectors: RHashMap<u16, AbstractRelayDistributionCollector>,
}

impl ExitDistributionCollector {
    fn new(consensus_weights: &PositionWeights, exit_ports: Vec<u16>) -> ExitDistributionCollector {
        let mut collectors: RHashMap<u16, AbstractRelayDistributionCollector> = RHashMap::default();

        for port in exit_ports {
            collectors.insert(
                port,
                AbstractRelayDistributionCollector::new(Position::Exit, consensus_weights),
            );
        }

        ExitDistributionCollector {
            collectors: collectors,
        }
    }
}

impl AbstractRelayDistributionFilteredPush for ExitDistributionCollector {
    fn filter(&self, relay: &Arc<TorCircuitRelay>) -> bool {
        if !relay.flags.contains(&Flag::Valid) {
            return false;
        }

        if !relay.flags.contains(&Flag::Running) {
            return false;
        }

        if !relay.flags.contains(&Flag::Exit) {
            return false;
        }

        if relay.flags.contains(&Flag::BadExit) {
            return false;
        }

        if let CondensedExitPolicy {
            policy_type: ExitPolicyType::Reject,
            ..
        } = relay.exit_policy
        {
            return false;
        }
        return true;
    }

    fn push_unfiltered(&mut self, relay: &Arc<TorCircuitRelay>) {
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
                    for (port, collector) in self.collectors.iter_mut() {
                        if rule.contains(*port) {
                            collector.push(relay);
                        }
                    }
                }
            }
        };
    }
}

struct TypeDependentWeights {
    exit: u64,
    guard: u64,
    guard_and_exit: u64,
    not_flagged: u64,
}

impl TypeDependentWeights {
    fn new(position: Position, consensus_weights: &PositionWeights) -> TypeDependentWeights {
        match position {
            Position::Guard => TypeDependentWeights {
                exit: 0,
                guard: consensus_weights.Wgg,
                guard_and_exit: consensus_weights.Wgd,
                not_flagged: consensus_weights.Wgm,
            },
            Position::Middle => TypeDependentWeights {
                exit: consensus_weights.Wme,
                guard: consensus_weights.Wmg,
                guard_and_exit: consensus_weights.Wmd,
                not_flagged: consensus_weights.Wmm,
            },
            Position::Exit => TypeDependentWeights {
                exit: consensus_weights.Wee,
                guard: consensus_weights.Weg,
                guard_and_exit: consensus_weights.Wed,
                not_flagged: consensus_weights.Wem,
            },
        }
    }

    fn get_weight_by_type(&self, relay_type: RelayType) -> u64 {
        match relay_type {
            RelayType::Exit => self.exit,
            RelayType::Guard => self.guard,
            RelayType::GuardAndExit => self.guard_and_exit,
            RelayType::NotFlagged => self.not_flagged,
        }
    }

    fn get_weight(&self, relay: &TorCircuitRelay) -> u64 {
        let relay_type = RelayType::from_relay(relay);
        self.get_weight_by_type(relay_type)
    }
}

/// A possibly unfinished version of a `RelayDistribution`
struct AbstractRelayDistributionCollector {
    bandwidth_sum: u64,
    weights: Vec<u64>,
    relays: Vec<Arc<TorCircuitRelay>>,
    type_dependent_weights: TypeDependentWeights,
}

impl AbstractRelayDistributionCollector {
    fn new(position: Position, consensus_weights: &PositionWeights) -> Self {
        AbstractRelayDistributionCollector {
            bandwidth_sum: 0,
            weights: Vec::new(),
            relays: Vec::new(),
            type_dependent_weights: TypeDependentWeights::new(position, consensus_weights),
        }
    }

    fn push(&mut self, relay: &Arc<TorCircuitRelay>) {
        let weight = relay.bandwidth * self.type_dependent_weights.get_weight(relay);
        self.relays.push(Arc::clone(relay));
        self.weights.push(weight);
        self.bandwidth_sum += weight;
    }
}

/// Derive the relay distributions per relay type from a provided list of
/// `TorCircuitRelay`
///
/// This returns a tuple containing three distributions: (guard, middle, exit).
/// Note that the exit "distribution" is in fact a map of distributions,
/// one for each requested exit port.
pub(crate) fn get_distributions(
    relays: &Vec<Arc<TorCircuitRelay>>,
    consensus_weights: PositionWeights,
    exit_ports: Vec<u16>,
) -> (
    RelayDistribution,
    RelayDistribution,
    RHashMap<u16, RelayDistribution>,
) {
    let mut guard_distr = GuardDistributionCollector::new(&consensus_weights);
    let mut middle_distr = MiddleDistributionCollector::new(&consensus_weights);
    let mut exit_distrs = ExitDistributionCollector::new(&consensus_weights, exit_ports);

    for relay in relays.iter() {
        // handle exit distributions
        guard_distr.filtered_push(relay);
        middle_distr.filtered_push(relay);
        exit_distrs.filtered_push(relay);
    }

    (
        // Guard
        guard_distr.collector.into(),
        // Middle
        middle_distr.collector.into(),
        // Exit
        exit_distrs
            .collectors
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect(),
    )
}
