//! Error type(s) for the circuit generator

use std::fmt;

/// An error that may occur when generating circuits.
#[derive(Debug)]
pub enum TorGeneratorError {
    // NoRelayFoundForThisPort(u16),
    UnableToSelectGuard,
    UnableToSelectExit(u16),
}

impl std::error::Error for TorGeneratorError {}

impl fmt::Display for TorGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // TorGeneratorError::NoRelayFoundForThisPort(port) => {
            //     write!(f, "Could not find a suitable relay for port: {}", port)
            // }
            TorGeneratorError::UnableToSelectGuard => {
                write!(f, "Could not select a guard relay")
            }
            TorGeneratorError::UnableToSelectExit(port) => {
                write!(f, "Could not select an exit relay for port: {}", port)
            }
        }
    }
}
