use tordoc;

use serde::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::rc::Rc;

use seeded_rand::RHashMap;
use tor_circuit_generator::{CircuitGenerator, TorCircuit, TorCircuitRelay};

#[derive(Serialize, Deserialize)]
pub struct CircSerde {
    pub guard: String,
    pub middle: String,
    pub exit: String,
}

impl CircSerde {
    pub fn from(circ: &TorCircuit) -> CircSerde {
        CircSerde {
            guard: circ.guard.fingerprint.to_string(),
            middle: circ.middle.first().unwrap().fingerprint.to_string(),
            exit: circ.guard.fingerprint.to_string(),
        }
    }
}

pub fn write_to_file(path: &str, circs: &Vec<TorCircuit>) {
    let serde_circs: Vec<CircSerde> = circs.iter().map(|circ| CircSerde::from(circ)).collect();
    std::fs::write(path, serde_json::to_string_pretty(&serde_circs).unwrap()).unwrap();
}

fn main() {
    println!("Benchmarking");
    let consensus_file_path = "../../data/2022-09-01-00-00-00-consensus";
    let torps_circuits_file_path = "../../data/circuits.txt";
    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(consensus_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        tordoc::Consensus::from_str(&raw).unwrap()
    };

    let descriptors = consensus.retrieve_descriptors(consensus_file_path).unwrap();

    let circuit_generator: CircuitGenerator =
        CircuitGenerator::new(&consensus, descriptors, vec![443]).unwrap();

    let mut ip_to_descmap: RHashMap<String, Rc<TorCircuitRelay>> = RHashMap::default();
    circuit_generator.relays.values().for_each(|relay| {
        relay.or_addresses.iter().for_each(|addr| {
            ip_to_descmap.insert(addr.ip.to_string(), Rc::clone(relay));
        })
    });

    let torps_epochs = parse_tor_circuit_file(torps_circuits_file_path, ip_to_descmap);

    println!("Start building circuits!");
    // let mut bench = Bench::new();
    let mut circs = vec![];
    for _ in 0..1000000 {
        match circuit_generator.build_circuit(3, 443) {
            Ok(circ) => circs.push(circ),
            Err(err) => {
                println!("{}", err);
            }
        }
    }

    /* Write generated circuits */
    write_to_file("../../data/circs_generated", &circs);
    write_to_file(
        "../../data/circs_torps",
        &torps_epochs.first().unwrap().circuits,
    );
}

#[allow(dead_code)]
struct TorPSEpoch {
    timestamp: u32,
    circuits: Vec<TorCircuit>,
}

fn parse_tor_circuit_file(
    tor_circuite_file_path: &str,
    ip_to_descmap: RHashMap<String, Rc<TorCircuitRelay>>,
) -> Vec<TorPSEpoch> {
    let file = File::open(tor_circuite_file_path).unwrap();
    let reader = BufReader::new(file);
    let mut epochs: Vec<TorPSEpoch> = vec![];

    let mut circuits: Vec<TorCircuit> = vec![];
    let mut lines = reader.lines();

    lines.next();
    let first_line = lines.next().unwrap().unwrap();
    let mut current_timestamp = 0;

    let split: Vec<&str> = first_line.split_whitespace().collect();
    match split[..] {
        [_sample, timestamp, guard, middle, exit, _] => {
            let timestamp: u32 = timestamp.parse().unwrap();
            current_timestamp = timestamp;
            let guard = ip_to_descmap.get(guard).unwrap();
            let middle = ip_to_descmap.get(middle).unwrap();
            let exit = ip_to_descmap.get(exit).unwrap();
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
    for line in lines {
        let line = match line {
            Err(err) => {
                println!("Error while parsing line: {err}");
                continue;
            }
            Ok(line) => line,
        };
        let split: Vec<&str> = line.split_whitespace().collect();
        match split[..] {
            [_sample, timestamp, guard, middle, exit, _] => {
                let timestamp: u32 = timestamp.parse().unwrap();
                if timestamp != current_timestamp {
                    println!("New Epoch started!");
                    break;
                    // epochs.push(TorPSEpoch {
                    //     timestamp: current_timestamp,
                    //     circuits: circuits.clone(),
                    // });
                    // current_timestamp = timestamp;
                    // circuits = vec![];
                }
                let guard = ip_to_descmap.get(guard).unwrap();
                let middle = ip_to_descmap.get(middle).unwrap();
                let exit = ip_to_descmap.get(exit).unwrap();
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
