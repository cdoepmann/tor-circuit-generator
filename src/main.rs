use torscaler::parser;
use torscaler::parser::consensus;

use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
pub mod lib;
use crate::lib::*;
use std::time::Instant;

fn main() {
    println!("Benchmarking");
    let asn_db_file_path = "data/GeoLite2-ASN-Blocks-IPv4.csv";
    let consensus_file_path = "data/test.consensus";
    let desc_file_path = "data/test.descriptors";

    let now = Instant::now();
    let asn_db = parser::asn::AsnDb::new(asn_db_file_path).unwrap();
    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(consensus_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_consensus(&raw, &asn_db).unwrap()
    };

    let elapsed = now.elapsed();
    println!("Parsing consensus: {:.2?}", elapsed);
    let now = Instant::now();
    let descriptors = {
        // Descriptors are given as a file
        let mut raw = String::new();
        let mut file = File::open(desc_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_descriptors(&raw).unwrap()
    };
    let elapsed = now.elapsed();
    println!("Parsing descriptors: {:.2?}", elapsed);
    let now = Instant::now();
    let circuit_generator: CircuitGenerator = CircuitGenerator::new(&consensus, descriptors);
    let elapsed = now.elapsed();
    println!("Preprocessing Cuircuit building: {:.2?}", elapsed);
    println!("Start building circuits!");
    let mut bench = Bench::new();
    let mut circs = vec![];
    for i in 0..100000 {
        bench.measure("Built 100.000 Circuits", i % 100000 == 0);
        match build_circuit(&circuit_generator, 3, 443) {
            Ok(circ) => circs.push(circ),
            Err(err) => {
                println!("{}", err);
            }
        }
    }
    bench.measure("", true);

    /* Sanity Check #1 */
    println!(
        "Guard weight:\t\t{}",
        circuit_generator.guard_distr.bandwidth_sum
    );
    println!(
        "Middle weight:\t\t{}",
        circuit_generator.middle_distr.bandwidth_sum
    );
    println!(
        "Exit (443) weight:\t{}",
        circuit_generator.exit_distr[443]
            .as_ref()
            .unwrap()
            .bandwidth_sum
    );

    //let relay_bw_sum = circuit_generator.relays.iter().reduce()
    /* Calculate max possible exit bandwidth */
    let mut sum = 0;
    for relay in circuit_generator.relays.into_iter() {
        let weight;
        let guard = consensus::Flag::Guard;
        let exit = consensus::Flag::Exit;

        if relay.flags.contains(&guard) && relay.flags.contains(&exit) {
            weight = *consensus.weights.get("Wed").unwrap();
        } else if relay.flags.contains(&exit) {
            weight = *consensus.weights.get("Wee").unwrap();
        } else if relay.flags.contains(&guard) {
            weight = *consensus.weights.get("Weg").unwrap();
        } else {
            weight = *consensus.weights.get("Wem").unwrap();
        }
        sum += weight * relay.bandwidth;
    }
    println!("Exit (Max) weight:\t{}", sum);

    println!("My expectaion would have been that this is \"kinda\" balanced");
    println!("Exit is already quite under represented. How does this look like for less used, but common ports?");
    // let reference_value = circuit_generator.exit_distr[63535]
    //     .as_ref()
    //     .unwrap()
    //     .bandwidth_sum;

    let mut port_bw_map: HashMap<u64, Vec<u16>> = HashMap::new();
    for port in 0..u16::MAX {
        if let Some(distr) = &circuit_generator.exit_distr[port as usize] {
            match port_bw_map.get_mut(&distr.bandwidth_sum) {
                Some(value) => {
                    value.push(port);
                }
                None => {
                    port_bw_map.insert(distr.bandwidth_sum, vec![port]);
                }
            }
        }
    }

    let mut keys = port_bw_map.keys().into_iter().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let value = port_bw_map.get(key).unwrap().clone();
        print!("Available Exit Bandwidth {} for ports: ", key);
        let mut start = value.first().unwrap();
        let mut prev: &u16 = start;
        for port in value.iter() {
            if *start == *port {
                prev = start;
                continue;
            }
            if *prev + 1 == *port {
                prev = port;
                continue;
            } else {
                if *start == *prev {
                    print!("{}, ", *start);
                } else {
                    print!("{}-{}, ", *start, *prev);
                }
                start = port;
                prev = port;
            }
        }
        if *start == *prev {
            print!("{}, ", *start);
        } else {
            print!("{}-{}, ", *start, *prev);
        }
        println!("");
    }

    println!("Done!");
}
