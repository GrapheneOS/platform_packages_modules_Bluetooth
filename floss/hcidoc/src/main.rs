#[macro_use]
extern crate num_derive;

mod parser;

use crate::parser::{LogParser, LogType};
use bt_packets;
use clap::{Arg, Command};

fn main() {
    let matches = Command::new("hcidoc")
        .version("0.1")
        .author("Abhishek Pandit-Subedi <abhishekpandit@google.com>")
        .about("Analyzes a linux HCI snoop log for specific behaviors and errors.")
        .arg(Arg::new("filename"))
        .get_matches();

    let filename = match matches.get_one::<String>("filename") {
        Some(f) => f,
        None => {
            println!("No filename parameter given.");
            return;
        }
    };

    let mut parser = match LogParser::new(filename.as_str()) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to load parser on {}: {}", filename, e);
            return;
        }
    };

    let log_type = match parser.read_log_type() {
        Ok(v) => v,
        Err(e) => {
            println!("Parsing {} failed: {}", filename, e);
            return;
        }
    };

    if let LogType::LinuxSnoop(header) = log_type {
        println!("Reading snoop file: {:?}", header);
        for (pos, v) in parser.get_snoop_iterator().expect("Not a linux snoop file").enumerate() {
            println!("#{} - Packet= {:?}, Index={}, Opcode={:?}", pos, v, v.index(), v.opcode());
            if pos > 100 {
                return;
            }
        }
    }
}
