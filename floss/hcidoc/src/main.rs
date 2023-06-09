use clap::{Arg, ArgAction, Command};
use std::io::Write;

mod engine;
mod groups;
mod parser;

use crate::engine::RuleEngine;
use crate::groups::{collisions, connections};
use crate::parser::{LinuxSnoopOpcodes, LogParser, LogType, Packet};

fn main() {
    let matches = Command::new("hcidoc")
        .version("0.1")
        .author("Abhishek Pandit-Subedi <abhishekpandit@google.com>")
        .about("Analyzes a linux HCI snoop log for specific behaviors and errors.")
        .arg(
            Arg::new("filename")
                .help("Path to the snoop log. If omitted, read from stdin instead."),
        )
        .arg(
            Arg::new("signals")
                .short('s')
                .action(ArgAction::SetTrue)
                .help("Report signals from active rules."),
        )
        .get_matches();

    let filename = match matches.get_one::<String>("filename") {
        Some(f) => f,
        None => "",
    };

    let report_signals = match matches.get_one::<bool>("signals") {
        Some(v) => *v,
        None => false,
    };

    let mut parser = match LogParser::new(filename) {
        Ok(p) => p,
        Err(e) => {
            println!(
                "Failed to load parser on {}: {}",
                if filename.len() == 0 { "stdin" } else { filename },
                e
            );
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

    // Create engine with default rule groups.
    let mut engine = RuleEngine::new();
    engine.add_rule_group("Collisions".into(), collisions::get_collisions_group());
    engine.add_rule_group("Connections".into(), connections::get_connections_group());

    // Decide where to write output.
    let mut writer: Box<dyn Write> = Box::new(std::io::stdout());

    if let LogType::LinuxSnoop(_header) = log_type {
        for (pos, v) in parser.get_snoop_iterator().expect("Not a linux snoop file").enumerate() {
            match Packet::try_from((pos, &v)) {
                Ok(p) => engine.process(p),
                Err(e) => match v.opcode() {
                    LinuxSnoopOpcodes::CommandPacket | LinuxSnoopOpcodes::EventPacket => {
                        eprintln!("#{}: {}", pos, e);
                    }
                    _ => (),
                },
            }
        }

        engine.report(&mut writer);
        if report_signals {
            let _ = writeln!(&mut writer, "### Signals ###");
            engine.report_signals(&mut writer);
        }
    }
}