//! Container types and data structures for bundling data needed for circuit
//! generation.

use std::fmt;
use std::rc::Rc;

use derive_builder::Builder;
use ipnet::IpNet;
use strum_macros::Display;
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

use tordoc::{consensus::CondensedExitPolicy, consensus::Flag, descriptor::OrAddress, Fingerprint};

/// A pair of IP network mask with exit port.
#[derive(Debug, Clone)]
pub struct OrAddressNet {
    pub ip: IpNet,
    pub port: u16,
}

/// A Tor relay, reduced to the properties needed for circuit selection.
#[derive(Debug, Builder, Clone)]
pub struct TorCircuitRelay {
    pub fingerprint: Fingerprint,
    pub family: Vec<Fingerprint>,
    pub or_addresses: Vec<OrAddress>,
    pub bandwidth: u64,
    pub flags: Vec<Flag>,
    /* For easier debugging */
    pub nickname: String,
    pub exit_policy: CondensedExitPolicy,
}

impl PartialEq for TorCircuitRelay {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl Eq for TorCircuitRelay {}

// https://docs.rs/rand/0.6.5/rand/distributions/struct.WeightedIndex.html
#[derive(Debug, EnumCountMacro, EnumIter, Display, Clone, Copy)]
pub(crate) enum RelayType {
    GuardAndExit = 0,
    Exit = 1,
    Guard = 2,
    NotFlagged = 3,
}

impl RelayType {
    pub(crate) fn from_relay(relay: &TorCircuitRelay) -> Self {
        /* There are more performant orders, but this is readable and I rather leave the optimization to the compiler */
        let guard = Flag::Guard;
        let exit = Flag::Exit;
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
}

#[derive(Debug, EnumCountMacro, EnumIter, Display, Clone, Copy)]
pub enum Position {
    Guard = 0,
    Middle = 1,
    Exit = 2,
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
