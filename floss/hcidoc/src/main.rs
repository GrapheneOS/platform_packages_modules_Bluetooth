#[macro_use]
extern crate num_derive;

mod parser;

use crate::parser::{LinuxSnoopOpcodes, LogParser, LogType, Packet};
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

    let mut printed = 0usize;
    if let LogType::LinuxSnoop(header) = log_type {
        println!("Reading snoop file: {:?}", header);
        for (pos, v) in parser.get_snoop_iterator().expect("Not a linux snoop file").enumerate() {
            if printed > 50 {
                break;
            }

            match Packet::try_from(&v) {
                Ok(p) => {
                    println!("#{}: {:?}", pos, p);
                    printed = printed + 1;
                }
                Err(e) => match v.opcode() {
                    LinuxSnoopOpcodes::CommandPacket | LinuxSnoopOpcodes::EventPacket => {
                        println!("#{}: {}", pos, e);
                        printed = printed + 1;
                    }
                    _ => (),
                },
            }
        }
    }
}
