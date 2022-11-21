use std::collections::hash_map::{Entry, HashMap};
use std::collections::HashSet;
use std::rc::Rc;

use torscaler::parser::DocumentCombiningError;
use torscaler::parser::Fingerprint;
use torscaler::parser::{consensus, descriptor};

use crate::bench;
use crate::containers::{TorCircuitRelay, TorCircuitRelayBuilder};

pub(crate) fn compute_range_from_port(
    port: &descriptor::ExitPolicyPort,
) -> impl IntoIterator<Item = usize> {
    match port {
        descriptor::ExitPolicyPort::Wildcard => {
            return 1..=u16::MAX.into();
        }
        descriptor::ExitPolicyPort::Port(value) => match value {
            descriptor::Range::Single(v) => return *v as usize..=*v as usize,
            descriptor::Range::Interval(v1, v2) => return *v1 as usize..=*v2 as usize,
        },
    }
}

pub(crate) fn compute_tor_circuit_relays<'a>(
    consensus: &'a consensus::ConsensusDocument,
    descriptors: Vec<torscaler::parser::descriptor::Descriptor>,
) -> Vec<Rc<TorCircuitRelay>> {
    println!("\tComputing Circuit Relays");
    // let mut missingDescriptors = 0;
    // let mut buildFailed = 0;
    let mut relays: Vec<Rc<TorCircuitRelay>> = vec![];
    let mut dropped_bandwidth_0 = 0;
    let mut droppped_not_running = 0;
    let mut bench = bench::Bench::new();

    bench.measure(
        "\t\t Compute Fingerprint -> Descriptor hashmap",
        bench::BENCH_ENABLED,
    );
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

    bench.measure("\t\t Nicknames to fingerprints", bench::BENCH_ENABLED);
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

    bench.measure("\t\t Consensus relays", bench::BENCH_ENABLED);
    println!("\t\t {} x ", consensus.relays.len());
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
    let mut first = true;
    for consensus_relay in consensus.relays.iter() {
        bench.measure("\t\t\t pre-checks", bench::BENCH_ENABLED && first);
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
            Err(_) => {
                // missingDescriptors += 1;
                continue;
            }
        };
        bench.measure("\t\t\t Init struct", bench::BENCH_ENABLED && first);
        let mut circuit_relay = TorCircuitRelayBuilder::default();
        circuit_relay.fingerprint(consensus_relay.fingerprint.clone());
        circuit_relay.bandwidth(consensus_relay.bandwidth_weight);
        bench.measure("\t\t\t Construct family", bench::BENCH_ENABLED && first);
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
        bench.measure("\t\t\t building", bench::BENCH_ENABLED && first);
        circuit_relay.nickname(descriptor.nickname.unwrap());
        let mut flags = vec![];
        for flag in consensus_relay.flags.iter() {
            flags.push(flag.clone());
        }
        circuit_relay.flags(flags);
        circuit_relay.or_addresses(descriptor.or_addresses.unwrap());
        circuit_relay.exit_policies(descriptor.exit_policy.unwrap());

        let relay = match circuit_relay.build() {
            Ok(circ_relay) => circ_relay,
            Err(err) => {
                println!("Error: {}", err.to_string());
                // buildFailed += 1;
                continue;
            }
        };

        relays.push(Rc::new(relay));
        bench.measure("", bench::BENCH_ENABLED);
        first = false;
    }
    //println!("Error summary:\n bandwidth 0: {},\n not running: {},\n missing Descriptors: {}\n build failed: {}\n", dropped_bandwidth_0, droppped_not_running, missingDescriptors, buildFailed);
    relays
}
