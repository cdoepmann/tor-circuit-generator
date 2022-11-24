use tordoc;

use crate::RHashMap;
use std::fs::File;
use std::io::prelude::*;
use std::time::Instant;
use tor_circuit_generator::*;

fn main() {
    println!("Benchmarking");
    let consensus_file_path = "/home/christoph/forschung/scalability-vs-anonymity/circuit-simulation/runs/horz-1.5/consensus/consensus";
    let desc_file_path = "/home/christoph/forschung/scalability-vs-anonymity/circuit-simulation/runs/horz-1.5/descriptors.all";

    let now = Instant::now();
    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(consensus_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        tordoc::Consensus::from_str(raw).unwrap()
    };

    let elapsed = now.elapsed();
    println!("Parsing consensus: {:.2?}", elapsed);
    let now = Instant::now();
    let descriptors = {
        // Descriptors are given as a file
        let mut raw = String::new();
        let mut file = File::open(desc_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        tordoc::Descriptor::many_from_str(raw).unwrap()
    };
    let elapsed = now.elapsed();
    println!("Parsing descriptors: {:.2?}", elapsed);
    let now = Instant::now();
    let circuit_generator: CircuitGenerator =
        CircuitGenerator::new(&consensus, descriptors, vec![443]);
    let elapsed = now.elapsed();
    println!("Preprocessing Cuircuit building: {:.2?}", elapsed);
    println!("Start building circuits!");
    // let mut bench = Bench::new();
    let mut circs = vec![];
    for _i in 0..1000000 {
        // bench.measure("Built 1.000.000 Circuits", i % 100000 == 0);
        match circuit_generator.build_circuit(3, 443) {
            Ok(circ) => circs.push(circ),
            Err(err) => {
                println!("{}", err);
            }
        }
    }
    // bench.measure("", true);

    println!("Saving to file");
    // let mut bench = Bench::new();

    let mut f = File::create("result.csv").unwrap();
    for circ in circs {
        writeln!(
            &mut f,
            "{},{},{}",
            circ.guard.fingerprint,
            circ.middle.get(0).unwrap().fingerprint,
            circ.exit.fingerprint
        )
        .unwrap();
    }
    // bench.measure("done writing", true);

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
        circuit_generator.exit_distrs[&443].bandwidth_sum
    );

    //let relay_bw_sum = circuit_generator.relays.iter().reduce()
    /* Calculate max possible exit bandwidth */
    let mut sum = 0;
    for relay in circuit_generator.relays.into_iter() {
        let weight;
        let guard = tordoc::consensus::Flag::Guard;
        let exit = tordoc::consensus::Flag::Exit;

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

    let mut port_bw_map: RHashMap<u64, Vec<u16>> = RHashMap::default();
    for port in 0..u16::MAX {
        if let Some(distr) = &circuit_generator.exit_distrs.get(&port) {
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
