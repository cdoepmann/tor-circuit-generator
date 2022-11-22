use std::collections::hash_map::{Entry, HashMap};
use std::collections::HashSet;
use std::rc::Rc;

use torscaler::parser::DocumentCombiningError;
use torscaler::parser::Fingerprint;
use torscaler::parser::{consensus, descriptor};

use crate::containers::{TorCircuitRelay, TorCircuitRelayBuilder};
use crate::mutual_agreement::MutualAgreement;

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
    // let mut missingDescriptors = 0;
    // let mut buildFailed = 0;
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
            Err(_) => {
                // missingDescriptors += 1;
                continue;
            }
        };
        let mut circuit_relay = TorCircuitRelayBuilder::default();
        circuit_relay.fingerprint(consensus_relay.fingerprint.clone());
        circuit_relay.bandwidth(consensus_relay.bandwidth_weight);
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
    }

    relays
}

/// Compute the symmetric subset of the family relation.
pub(crate) fn compute_families(relays: &Vec<Rc<TorCircuitRelay>>) -> MutualAgreement {
    let mut agreement = MutualAgreement::new();

    for relay in relays {
        let relay_fingerprint_str = format!("{}", relay.fingerprint);
        for family_fingerprint in &relay.family {
            let family_fingerprint_str = format!("{}", family_fingerprint);
            agreement.agree(&relay_fingerprint_str, &family_fingerprint_str);
        }
    }

    agreement
}
