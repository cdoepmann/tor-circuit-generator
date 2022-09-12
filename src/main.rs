use torscaler::parser;

use std::fs::File;
use std::io::prelude::*;
pub mod lib;
use crate::lib::*;

fn main() {
    println!("Hello, world!");
    let asn_db_file_path = "data/GeoLite2-ASN-Blocks-IPv4.csv";
    let consensus_file_path = "data/test.consensus";
    let desc_file_path = "data/test.descriptors";
    let asn_db = parser::asn::AsnDb::new(asn_db_file_path).unwrap();
    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(consensus_file_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_consensus(&raw, &asn_db).unwrap()
    };

    let descriptors = {
            // Descriptors are given as a file
            let mut raw = String::new();
            let mut file = File::open(desc_file_path).unwrap();
            file.read_to_string(&mut raw).unwrap();
            parser::parse_descriptors(&raw).unwrap()
    };

    let circuit_generator : CircuitGenerator = CircuitGenerator::new(&consensus, descriptors);

    println!("Start building circuits!");
    for i in 0..100000 {
        let mut circs = vec![];
        //let port = (i % 65535);
        match build_circuit(&circuit_generator, 3, 443) {
            Ok(circ) => {circs.push(circ)},
            Err(err) => {println!("{}",err);},
        }
    }
    println!("Done!");
}
