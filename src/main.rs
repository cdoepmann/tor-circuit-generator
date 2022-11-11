use torscaler::parser;
use torscaler::parser::consensus;

use std::char::MAX;
use std::collections::HashMap;
use std::fs::File;
use std::hash::Hash;
use std::io::prelude::*;
pub mod lib;
use crate::lib::*;
use serde::*;
use serde_json::*;
use std::fs;
use std::io::BufReader;
use std::rc::Rc;
use std::time::Instant;

struct RelayData {
    arti: u64,
    tcg: u64,
}
impl Default for RelayData {
    fn default() -> Self {
        RelayData { arti: 0, tcg: 0 }
    }
}
struct RelaySummary {
    pub guard: RelayData,
    pub middle: RelayData,
    pub exit: RelayData,
}
impl Default for RelaySummary {
    fn default() -> Self {
        RelaySummary {
            guard: RelayData::default(),
            middle: RelayData::default(),
            exit: RelayData::default(),
        }
    }
}

fn main() {
    println!("Benchmarking");
    let asn_db_file_path = "../../data/GeoLite2-ASN-Blocks-IPv4.csv";
    let consensus_file_path = "../../data/2022-09-01-00-00-00-consensus";
    let torps_circuits_file_path = "../../data/circuits.txt";
    let asn_db = parser::asn::AsnDb::new(asn_db_file_path).unwrap();
    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(consensus_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_consensus(&raw, &asn_db).unwrap()
    };

    let descriptors =
        torscaler::highlevel::lookup_descriptors(&consensus, consensus_file_path).unwrap();

    let circuit_generator: CircuitGenerator = CircuitGenerator::new(&consensus, descriptors);

    let mut ip2descMap: HashMap<String, Rc<TorCircuitRelay>> = HashMap::new();
    circuit_generator.relays.iter().for_each(|relay| {
        relay.or_addresses.iter().for_each(|addr| {
            ip2descMap.insert(addr.ip.to_string(), Rc::clone(relay));
        })
    });

    let torps_epochs = parse_tor_circuit_file(torps_circuits_file_path, ip2descMap);

    println!("Start building circuits!");
    let mut bench = Bench::new();
    let mut circs = vec![];
    for i in 0..1000000 {
        match build_circuit(&circuit_generator, 3, 443) {
            Ok(circ) => circs.push(circ),
            Err(err) => {
                println!("{}", err);
            }
        }
    }

    /* Write generated circuits */
    write_to_file("../../data/circs_generated", &circs);
    write_to_file("../../data/circs_torps", &torps_epochs.first().unwrap().circuits);

}

struct TorPSEpoch {
    timestamp: u32,
    circuits: Vec<TorCircuit>,
}

fn parse_tor_circuit_file(
    tor_circuite_file_path: &str,
    ip2descMap: HashMap<String, Rc<TorCircuitRelay>>,
) -> Vec<TorPSEpoch> {
    let mut file = File::open(tor_circuite_file_path).unwrap();
    let reader = BufReader::new(file);
    let mut epochs: Vec<TorPSEpoch> = vec![];

    let mut circuits: Vec<TorCircuit> = vec![];
    let mut lines = reader.lines();

    lines.next();
    let first_line = lines.next().unwrap().unwrap();
    let mut current_timestamp = 0;

    let split: Vec<&str> = first_line.split_whitespace().collect();
        match split[..] {
            [sample, timestamp, guard, middle, exit, _] => {
                let timestamp: u32 = timestamp.parse().unwrap();
                current_timestamp = timestamp;
                let guard = ip2descMap.get(guard).unwrap();
                let middle = ip2descMap.get(middle).unwrap();
                let exit = ip2descMap.get(exit).unwrap();
                circuits.push(TorCircuit {
                    guard: Rc::clone(guard),
                    middle: vec![Rc::clone(middle)],
                    exit: Rc::clone(exit),
                })
            }
            _ => {
                println!("FAILED")
            }
        }
    for line in lines{
        let line = match line {
            Err(err) => {
                println!("Error while parsing line: {err}");
                continue;
            }
            Ok(line) => line,
        };
        let split: Vec<&str> = line.split_whitespace().collect();
        match split[..] {
            [sample, timestamp, guard, middle, exit, _] => {
                let timestamp: u32 = timestamp.parse().unwrap();
                if timestamp != current_timestamp {
                    println!("New Epoch started!");
                    break;
                    epochs.push(TorPSEpoch {
                        timestamp: current_timestamp,
                        circuits: circuits.clone(),
                    });
                    current_timestamp = timestamp;
                    circuits = vec![];
                }
                let guard = ip2descMap.get(guard).unwrap();
                let middle = ip2descMap.get(middle).unwrap();
                let exit = ip2descMap.get(exit).unwrap();
                circuits.push(TorCircuit {
                    guard: Rc::clone(guard),
                    middle: vec![Rc::clone(middle)],
                    exit: Rc::clone(exit),
                })
            }
            _ => {
                println!("FAILED")
            }
        }
    }
    epochs.push(TorPSEpoch {
        timestamp: current_timestamp,
        circuits: circuits.clone(),
    });
    epochs
}
