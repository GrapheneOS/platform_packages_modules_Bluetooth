///! Rule group for tracking controller related issues.
use chrono::NaiveDateTime;
use std::convert::Into;
use std::io::Write;

use crate::engine::{Rule, RuleGroup, Signal};
use crate::parser::{Packet, PacketChild};
use bt_packets::hci::EventChild;

enum ControllerSignal {
    HardwareError, // Controller reports HCI event: Hardware Error
}

impl Into<&'static str> for ControllerSignal {
    fn into(self) -> &'static str {
        match self {
            ControllerSignal::HardwareError => "HardwareError",
        }
    }
}

struct ControllerRule {
    /// Pre-defined signals discovered in the logs.
    signals: Vec<Signal>,

    /// Interesting occurrences surfaced by this rule.
    reportable: Vec<(NaiveDateTime, String)>,
}

impl ControllerRule {
    pub fn new() -> Self {
        ControllerRule { signals: vec![], reportable: vec![] }
    }

    pub fn report_hardware_error(&mut self, packet: &Packet) {
        self.signals.push(Signal {
            index: packet.index,
            ts: packet.ts.clone(),
            tag: ControllerSignal::HardwareError.into(),
        });

        self.reportable.push((packet.ts, format!("controller reported hardware error")));
    }
}

impl Rule for ControllerRule {
    fn process(&mut self, packet: &Packet) {
        match &packet.inner {
            PacketChild::HciEvent(ev) => match ev.specialize() {
                EventChild::HardwareError(_ev) => {
                    self.report_hardware_error(&packet);
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn report(&self, writer: &mut dyn Write) {
        if self.reportable.len() > 0 {
            let _ = writeln!(writer, "Controller report:");
            for (ts, message) in self.reportable.iter() {
                let _ = writeln!(writer, "[{:?}] {}", ts, message);
            }
        }
    }

    fn report_signals(&self) -> &[Signal] {
        self.signals.as_slice()
    }
}

/// Get a rule group with connection rules.
pub fn get_controllers_group() -> RuleGroup {
    let mut group = RuleGroup::new();
    group.add_rule(Box::new(ControllerRule::new()));

    group
}
