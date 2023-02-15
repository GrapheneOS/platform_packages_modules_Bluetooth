//! Handles stream processing of commands and events.

use std::collections::HashMap;
use std::io::Write;

use crate::parser::Packet;

/// Trait that describes a single rule processor. A rule should be used to represent a certain type
/// of analysis (for example: ACL Connections rule may keep track of all ACL connections and report
/// on failed connections).
pub trait Rule {
    /// Process a single packet.
    fn process(&mut self, packet: &Packet);

    /// Generate a report for this rule based on the input stream so far. Usually, this should
    /// report on the instances of this rule that were discovered or any error conditions that are
    /// relevant to this rule.
    fn report(&self, writer: &mut dyn Write);
}

/// Grouping of rules. This is used to make it easier to enable/disable certain rules for
/// processing a file.
pub struct RuleGroup {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleGroup {
    pub fn new() -> Self {
        RuleGroup { rules: vec![] }
    }

    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn process(&mut self, packet: &Packet) {
        for rule in &mut self.rules {
            rule.process(packet);
        }
    }

    pub fn report(&mut self, writer: &mut dyn Write) {
        for rule in &self.rules {
            rule.report(writer);
        }
    }
}
/// Main entry point to process input data and run rules on them.
pub struct RuleEngine {
    groups: HashMap<String, RuleGroup>,
}

impl RuleEngine {
    pub fn new() -> Self {
        RuleEngine { groups: HashMap::new() }
    }

    pub fn add_rule_group(&mut self, name: String, group: RuleGroup) {
        self.groups.insert(name, group);
    }

    /// Consume a packet and run it through the various rules processors.
    pub fn process(&mut self, packet: Packet) {
        for group in self.groups.values_mut() {
            group.process(&packet);
        }
    }

    pub fn report(&mut self, writer: &mut dyn Write) {
        for group in self.groups.values_mut() {
            group.report(writer);
        }
    }
}
