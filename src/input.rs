use std::collections::hash_map::Entry;
use std::error::Error;
use std::rc::Rc;

use tordoc::{
    consensus::CondensedExitPolicy, consensus::Flag, consensus::Relay, descriptor::FamilyMember,
    descriptor::OrAddress, error::DocumentCombiningError, Consensus, Descriptor, Fingerprint,
};

use crate::containers::TorCircuitRelay;
use crate::mutual_agreement::MutualAgreement;
use fromsuper::FromSuper;
use seeded_rand::{RHashMap, RHashSet};

#[derive(Debug, FromSuper)]
#[fromsuper(from_type = "Descriptor", unpack = true)]
struct MyDescriptor {
    digest: Fingerprint,
    family_members: Vec<FamilyMember>,
    nickname: String,
    or_addresses: Vec<OrAddress>,
}

#[derive(FromSuper)]
#[fromsuper(from_type = "&'a Relay", unpack = true, make_refs = true)]
struct MyRelay<'a> {
    pub fingerprint: &'a Fingerprint,
    pub digest: &'a Fingerprint,
    pub bandwidth_weight: &'a u64,
    pub flags: &'a Vec<Flag>,
    /* For easier debugging */
    pub nickname: &'a String,
    pub exit_policy: &'a CondensedExitPolicy,
}

pub(crate) fn compute_tor_circuit_relays<'a>(
    consensus: &'a Consensus,
    descriptors: Vec<Descriptor>,
) -> Result<Vec<Rc<TorCircuitRelay>>, Box<dyn Error + Send + Sync>> {
    // let mut missingDescriptors = 0;
    // let mut buildFailed = 0;
    let mut relays: Vec<Rc<TorCircuitRelay>> = vec![];
    let mut dropped_bandwidth_0 = 0;
    let mut droppped_not_running = 0;

    // unpack consensus relays
    let consensus_relays: Vec<MyRelay> = consensus
        .relays
        .iter()
        .map(|r| r.try_into())
        .collect::<Result<_, _>>()?;

    // unpack descriptors
    let descriptors: Vec<MyDescriptor> = descriptors
        .into_iter()
        .map(|d| d.try_into())
        .collect::<Result<Vec<_>, _>>()?;

    let mut descriptors: RHashMap<Fingerprint, MyDescriptor> = descriptors
        .into_iter()
        .map(|d| (d.digest.clone(), d))
        .collect();

    let mut nicknames_to_fingerprints: RHashMap<String, Option<Fingerprint>> = RHashMap::default();
    {
        for relay in consensus_relays.iter() {
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

    let known_fingerprints: RHashSet<Fingerprint> = consensus_relays
        .iter()
        .map(|r| r.fingerprint.clone())
        .collect();

    let filter_family_member = |f: FamilyMember| match f {
        FamilyMember::Fingerprint(fingerprint) => {
            if known_fingerprints.contains(&fingerprint) {
                Some(fingerprint)
            } else {
                None
            }
        }
        FamilyMember::Nickname(nickname) => {
            if let Some(entry) = nicknames_to_fingerprints.get(&nickname) {
                if let Some(fingerprint) = entry {
                    return Some(fingerprint.clone());
                }
            }
            None
        }
    };
    for consensus_relay in consensus_relays.iter() {
        let result = descriptors.remove(&consensus_relay.digest).ok_or_else(|| {
            DocumentCombiningError::MissingDescriptor {
                digest: consensus_relay.digest.to_string(),
            }
        });
        if *consensus_relay.bandwidth_weight == 0 {
            /*println!(
                "WARNING: Descriptor: {} has Consensus bandwidth of 0 and is dropped!",
                descriptor.nickname
            );*/
            dropped_bandwidth_0 = dropped_bandwidth_0 + 1;
            continue;
        }

        let flag_running = Flag::Running;
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

        let relay = {
            let mut flags = vec![];
            for flag in consensus_relay.flags.iter() {
                flags.push(flag.clone());
            }

            TorCircuitRelay {
                fingerprint: consensus_relay.fingerprint.clone(),
                bandwidth: *consensus_relay.bandwidth_weight,
                family: descriptor
                    .family_members
                    .into_iter()
                    // keep only family members that do exist, and convert them to fingerprints
                    .filter_map(filter_family_member)
                    .collect(),
                nickname: descriptor.nickname,
                flags: flags,
                or_addresses: descriptor.or_addresses,
                exit_policy: consensus_relay.exit_policy.clone(),
            }
        };

        relays.push(Rc::new(relay));
    }

    Ok(relays)
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
