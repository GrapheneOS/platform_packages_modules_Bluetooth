///! Rule group for tracking connection related issues.
use chrono::NaiveDateTime;
use std::collections::{HashMap, VecDeque};
use std::convert::Into;
use std::io::Write;

use crate::engine::{Rule, RuleGroup, Signal};
use crate::parser::{Packet, PacketChild};
use bt_packets::hci::{
    Acl, AclCommandChild, Address, CommandChild, CommandStatus, ConnectionManagementCommandChild,
    DisconnectReason, ErrorCode, Event, EventChild, LeConnectionManagementCommandChild,
    LeMetaEventChild, NumberOfCompletedPackets, OpCode, ScoConnectionCommandChild,
    SecurityCommandChild, SubeventCode,
};

enum ConnectionSignal {
    LinkKeyMismatch, // Peer forgets the link key or it mismatches ours
    NocpDisconnect,  // Peer is disconnected when NOCP packet isn't yet received
    NocpTimeout,     // Host doesn't receive NOCP packet 5 seconds after ACL is sent
}

impl Into<&'static str> for ConnectionSignal {
    fn into(self) -> &'static str {
        match self {
            ConnectionSignal::LinkKeyMismatch => "LinkKeyMismatch",
            ConnectionSignal::NocpDisconnect => "Nocp",
            ConnectionSignal::NocpTimeout => "Nocp",
        }
    }
}

/// Valid values are in the range 0x0000-0x0EFF.
pub type ConnectionHandle = u16;

/// Arbitrary invalid connection handle.
pub const INVALID_CONN_HANDLE: u16 = 0xfffeu16;

/// When we attempt to create a sco connection on an unknown handle, use this address as
/// a placeholder.
pub const UNKNOWN_SCO_ADDRESS: [u8; 6] = [0xdeu8, 0xad, 0xbe, 0xef, 0x00, 0x00];

/// Any outstanding NOCP or disconnection that is more than 5s away from the sent ACL packet should
/// result in an NOCP signal being generated.
pub const NOCP_CORRELATION_TIME_MS: i64 = 5000;

pub(crate) struct NocpData {
    /// Number of in-flight packets without a corresponding NOCP.
    pub inflight_acl_ts: VecDeque<NaiveDateTime>,
}

impl NocpData {
    fn new() -> Self {
        Self { inflight_acl_ts: VecDeque::new() }
    }
}

/// Keeps track of connections and identifies odd disconnections.
struct OddDisconnectionsRule {
    /// Handles that had successful complete connections. The value has the timestamp of the
    /// connection completion and the address of the device.
    active_handles: HashMap<ConnectionHandle, (NaiveDateTime, Address)>,

    connection_attempt: HashMap<Address, Packet>,
    last_connection_attempt: Option<Address>,

    le_connection_attempt: HashMap<Address, Packet>,
    last_le_connection_attempt: Option<Address>,

    sco_connection_attempt: HashMap<Address, Packet>,
    last_sco_connection_attempt: Option<Address>,

    /// Keep track of some number of |Number of Completed Packets| and filter to
    /// identify bursts.
    nocp_by_handle: HashMap<ConnectionHandle, NocpData>,

    /// Pre-defined signals discovered in the logs.
    signals: Vec<Signal>,

    /// Interesting occurrences surfaced by this rule.
    reportable: Vec<(NaiveDateTime, String)>,
}

impl OddDisconnectionsRule {
    pub fn new() -> Self {
        OddDisconnectionsRule {
            active_handles: HashMap::new(),
            connection_attempt: HashMap::new(),
            last_connection_attempt: None,
            le_connection_attempt: HashMap::new(),
            last_le_connection_attempt: None,
            sco_connection_attempt: HashMap::new(),
            last_sco_connection_attempt: None,
            nocp_by_handle: HashMap::new(),
            signals: vec![],
            reportable: vec![],
        }
    }

    fn process_classic_connection(
        &mut self,
        conn: &ConnectionManagementCommandChild,
        packet: &Packet,
    ) {
        let has_existing = match conn {
            ConnectionManagementCommandChild::CreateConnection(cc) => {
                self.last_connection_attempt = Some(cc.get_bd_addr());
                self.connection_attempt.insert(cc.get_bd_addr(), packet.clone())
            }

            ConnectionManagementCommandChild::AcceptConnectionRequest(ac) => {
                self.last_connection_attempt = Some(ac.get_bd_addr());
                self.connection_attempt.insert(ac.get_bd_addr(), packet.clone())
            }

            _ => None,
        };

        if let Some(p) = has_existing {
            self.reportable.push((
                p.ts,
                format!("Dangling connection attempt at {:?} replaced with {:?}", p, packet),
            ));
        }
    }

    fn process_sco_connection(&mut self, sco_conn: &ScoConnectionCommandChild, packet: &Packet) {
        let handle = match sco_conn {
            ScoConnectionCommandChild::SetupSynchronousConnection(ssc) => {
                ssc.get_connection_handle()
            }

            ScoConnectionCommandChild::EnhancedSetupSynchronousConnection(essc) => {
                essc.get_connection_handle()
            }

            _ => INVALID_CONN_HANDLE,
        };

        let unknown_address = Address::from(&UNKNOWN_SCO_ADDRESS);
        let address = match self.active_handles.get(&handle).as_ref() {
            Some((_ts, address)) => address,
            None => &unknown_address,
        };

        let has_existing = match sco_conn {
            ScoConnectionCommandChild::SetupSynchronousConnection(_)
            | ScoConnectionCommandChild::EnhancedSetupSynchronousConnection(_) => {
                self.last_sco_connection_attempt = Some(address.clone());
                self.sco_connection_attempt.insert(address.clone(), packet.clone())
            }

            ScoConnectionCommandChild::AcceptSynchronousConnection(asc) => {
                self.last_sco_connection_attempt = Some(asc.get_bd_addr());
                self.sco_connection_attempt.insert(asc.get_bd_addr(), packet.clone())
            }

            ScoConnectionCommandChild::EnhancedAcceptSynchronousConnection(easc) => {
                self.last_sco_connection_attempt = Some(easc.get_bd_addr());
                self.sco_connection_attempt.insert(easc.get_bd_addr(), packet.clone())
            }

            _ => None,
        };

        if let Some(p) = has_existing {
            self.reportable.push((
                p.ts,
                format!("Dangling sco connection attempt at {:?} replaced with {:?}", p, packet),
            ));
        }
    }

    fn process_le_conn_connection(
        &mut self,
        le_conn: &LeConnectionManagementCommandChild,
        packet: &Packet,
    ) {
        let has_existing = match le_conn {
            LeConnectionManagementCommandChild::LeCreateConnection(create) => {
                self.last_le_connection_attempt = Some(create.get_peer_address());
                self.le_connection_attempt.insert(create.get_peer_address().clone(), packet.clone())
            }

            LeConnectionManagementCommandChild::LeExtendedCreateConnection(extcreate) => {
                self.last_le_connection_attempt = Some(extcreate.get_peer_address());
                self.le_connection_attempt
                    .insert(extcreate.get_peer_address().clone(), packet.clone())
            }

            _ => None,
        };

        if let Some(p) = has_existing {
            self.reportable.push((
                p.ts,
                format!("Dangling LE connection attempt at {:?} replaced with {:?}", p, packet),
            ));
        }
    }

    fn process_command_status(&mut self, cs: &CommandStatus, packet: &Packet) {
        // Clear last connection attempt since it was successful.
        let last_address = match cs.get_command_op_code() {
            OpCode::CreateConnection | OpCode::AcceptConnectionRequest => {
                self.last_connection_attempt.take()
            }

            OpCode::SetupSynchronousConnection
            | OpCode::AcceptSynchronousConnection
            | OpCode::EnhancedSetupSynchronousConnection
            | OpCode::EnhancedAcceptSynchronousConnection => {
                self.last_sco_connection_attempt.take()
            }

            OpCode::LeCreateConnection | OpCode::LeExtendedCreateConnection => {
                self.last_le_connection_attempt.take()
            }

            _ => None,
        };

        if let Some(address) = last_address {
            if cs.get_status() != ErrorCode::Success {
                self.reportable.push((
                    packet.ts,
                    format!("Failing command status on [{}]: {:?}", address, cs),
                ));

                // Also remove the connection attempt.
                match cs.get_command_op_code() {
                    OpCode::CreateConnection | OpCode::AcceptConnectionRequest => {
                        self.connection_attempt.remove(&address);
                    }

                    OpCode::SetupSynchronousConnection
                    | OpCode::AcceptSynchronousConnection
                    | OpCode::EnhancedSetupSynchronousConnection
                    | OpCode::EnhancedAcceptSynchronousConnection => {
                        self.sco_connection_attempt.remove(&address);
                    }

                    OpCode::LeCreateConnection => {
                        self.le_connection_attempt.remove(&address);
                    }

                    _ => (),
                }
            }
        } else {
            if cs.get_status() != ErrorCode::Success {
                self.reportable.push((
                    packet.ts,
                    format!("Failing command status on unknown address: {:?}", cs),
                ));
            }
        }
    }

    fn process_event(&mut self, ev: &Event, packet: &Packet) {
        match ev.specialize() {
            EventChild::ConnectionComplete(cc) => {
                match self.connection_attempt.remove(&cc.get_bd_addr()) {
                    Some(_) => {
                        if cc.get_status() == ErrorCode::Success {
                            self.active_handles
                                .insert(cc.get_connection_handle(), (packet.ts, cc.get_bd_addr()));
                        } else {
                            self.reportable.push((
                                packet.ts,
                                format!(
                                    "ConnectionComplete error {:?} for addr {} (handle={})",
                                    cc.get_status(),
                                    cc.get_bd_addr(),
                                    cc.get_connection_handle()
                                ),
                            ));
                        }
                    }
                    None => {
                        self.reportable.push((
                            packet.ts,
                            format!(
                            "ConnectionComplete with status {:?} for unknown addr {} (handle={})",
                            cc.get_status(),
                            cc.get_bd_addr(),
                            cc.get_connection_handle()
                        ),
                        ));
                    }
                }
            }

            EventChild::DisconnectionComplete(dsc) => {
                let handle = dsc.get_connection_handle();
                self.active_handles.remove(&handle);

                // Check if this is a NOCP type disconnection and flag it.
                match self.nocp_by_handle.get_mut(&handle) {
                    Some(nocp_data) => {
                        if let Some(acl_front_ts) = nocp_data.inflight_acl_ts.pop_front() {
                            self.signals.push(Signal {
                                index: packet.index,
                                ts: packet.ts.clone(),
                                tag: ConnectionSignal::NocpDisconnect.into(),
                            });

                            self.reportable.push((
                                        packet.ts,
                                        format!("DisconnectionComplete for handle({}) showed incomplete in-flight ACL at {}",
                                        handle, acl_front_ts)));
                        }
                    }
                    None => (),
                }

                // Remove nocp information for handles that were removed.
                self.nocp_by_handle.remove(&handle);
            }

            EventChild::SynchronousConnectionComplete(scc) => {
                match self.sco_connection_attempt.remove(&scc.get_bd_addr()) {
                    Some(_) => {
                        if scc.get_status() == ErrorCode::Success {
                            self.active_handles.insert(
                                scc.get_connection_handle(),
                                (packet.ts, scc.get_bd_addr()),
                            );
                        } else {
                            self.reportable.push((
                                packet.ts,
                                format!(
                                    "SynchronousConnectionComplete error {:?} for addr {} (handle={})",
                                    scc.get_status(),
                                    scc.get_bd_addr(),
                                    scc.get_connection_handle()
                                ),
                            ));
                        }
                    }
                    None => {
                        self.reportable.push((
                            packet.ts,
                            format!(
                            "SynchronousConnectionComplete with status {:?} for unknown addr {} (handle={})",
                            scc.get_status(),
                            scc.get_bd_addr(),
                            scc.get_connection_handle()
                        ),
                        ));
                    }
                }
            }

            EventChild::LeMetaEvent(lme) => {
                let details = match lme.specialize() {
                    LeMetaEventChild::LeConnectionComplete(lcc) => Some((
                        lcc.get_status(),
                        lcc.get_connection_handle(),
                        lcc.get_peer_address(),
                    )),
                    LeMetaEventChild::LeEnhancedConnectionComplete(lecc) => Some((
                        lecc.get_status(),
                        lecc.get_connection_handle(),
                        lecc.get_peer_address(),
                    )),
                    _ => None,
                };

                if let Some((status, handle, address)) = details {
                    match self.le_connection_attempt.remove(&address) {
                        Some(_) => {
                            if status == ErrorCode::Success {
                                self.active_handles.insert(handle, (packet.ts, address));
                            } else {
                                self.reportable.push((
                                    packet.ts,
                                    format!(
                                        "LeConnectionComplete error {:?} for addr {} (handle={})",
                                        status, address, handle
                                    ),
                                ));
                            }
                        }
                        None => {
                            self.reportable.push((packet.ts, format!("LeConnectionComplete with status {:?} for unknown addr {} (handle={})", status, address, handle)));
                        }
                    }
                }
            }

            _ => (),
        }
    }

    fn process_acl_tx(&mut self, acl_tx: &Acl, packet: &Packet) {
        let handle = acl_tx.get_handle();

        // Insert empty Nocp data for handle if it doesn't exist.
        if !self.nocp_by_handle.contains_key(&handle) {
            self.nocp_by_handle.insert(handle, NocpData::new());
        }

        if let Some(nocp_data) = self.nocp_by_handle.get_mut(&handle) {
            nocp_data.inflight_acl_ts.push_back(packet.ts.clone());
        }
    }

    fn process_nocp(&mut self, nocp: &NumberOfCompletedPackets, packet: &Packet) {
        let ts = &packet.ts;
        for completed_packet in nocp.get_completed_packets() {
            let handle = completed_packet.connection_handle;
            if !self.nocp_by_handle.contains_key(&handle) {
                self.nocp_by_handle.insert(handle, NocpData::new());
            }

            if let Some(nocp_data) = self.nocp_by_handle.get_mut(&handle) {
                if let Some(acl_front_ts) = nocp_data.inflight_acl_ts.pop_front() {
                    let duration_since_acl = ts.signed_duration_since(acl_front_ts);
                    if duration_since_acl.num_milliseconds() > NOCP_CORRELATION_TIME_MS {
                        self.signals.push(Signal {
                            index: packet.index,
                            ts: packet.ts.clone(),
                            tag: ConnectionSignal::NocpTimeout.into(),
                        });
                        self.reportable.push((
                            packet.ts,
                            format!(
                                "Nocp sent {} ms after ACL on handle({}).",
                                duration_since_acl.num_milliseconds(),
                                handle
                            ),
                        ));
                    }
                }
            }
        }
    }

    fn process_reset(&mut self) {
        self.active_handles.clear();
        self.connection_attempt.clear();
        self.last_connection_attempt = None;
        self.le_connection_attempt.clear();
        self.last_le_connection_attempt = None;
        self.sco_connection_attempt.clear();
        self.last_sco_connection_attempt = None;
        self.nocp_by_handle.clear();
    }
}

impl Rule for OddDisconnectionsRule {
    fn process(&mut self, packet: &Packet) {
        match &packet.inner {
            PacketChild::HciCommand(cmd) => match cmd.specialize() {
                CommandChild::AclCommand(aclpkt) => match aclpkt.specialize() {
                    AclCommandChild::ConnectionManagementCommand(conn) => {
                        self.process_classic_connection(&conn.specialize(), packet);
                    }
                    AclCommandChild::ScoConnectionCommand(sco_conn) => {
                        self.process_sco_connection(&sco_conn.specialize(), packet);
                    }
                    AclCommandChild::LeConnectionManagementCommand(le_conn) => {
                        self.process_le_conn_connection(&le_conn.specialize(), packet);
                    }
                    AclCommandChild::Disconnect(dc_conn) => {
                        // If reason is power off, the host might not wait for connection complete event
                        if dc_conn.get_reason()
                            == DisconnectReason::RemoteDeviceTerminatedConnectionPowerOff
                        {
                            let handle = dc_conn.get_connection_handle();
                            self.active_handles.remove(&handle);
                            self.nocp_by_handle.remove(&handle);
                        }
                    }

                    // end acl pkt
                    _ => (),
                },
                CommandChild::Reset(_) => {
                    self.process_reset();
                }

                // end hci command
                _ => (),
            },

            PacketChild::HciEvent(ev) => match ev.specialize() {
                EventChild::CommandStatus(cs) => match cs.get_command_op_code() {
                    OpCode::CreateConnection
                    | OpCode::AcceptConnectionRequest
                    | OpCode::SetupSynchronousConnection
                    | OpCode::AcceptSynchronousConnection
                    | OpCode::EnhancedSetupSynchronousConnection
                    | OpCode::EnhancedAcceptSynchronousConnection
                    | OpCode::LeCreateConnection
                    | OpCode::LeExtendedCreateConnection => {
                        self.process_command_status(&cs, packet);
                    }

                    // end command status
                    _ => (),
                },

                EventChild::ConnectionComplete(_)
                | EventChild::DisconnectionComplete(_)
                | EventChild::SynchronousConnectionComplete(_) => {
                    self.process_event(&ev, packet);
                }

                EventChild::LeMetaEvent(lme) => match lme.get_subevent_code() {
                    SubeventCode::ConnectionComplete | SubeventCode::EnhancedConnectionComplete => {
                        self.process_event(&ev, packet);
                    }
                    _ => (),
                },

                EventChild::NumberOfCompletedPackets(nocp) => {
                    self.process_nocp(&nocp, packet);
                }

                // end hci event
                _ => (),
            },

            // Use tx packets for nocp tracking.
            PacketChild::AclTx(tx) => {
                self.process_acl_tx(&tx, packet);
            }

            // We don't do anything with RX packets yet.
            PacketChild::AclRx(_) => (),
        }
    }

    fn report(&self, writer: &mut dyn Write) {
        if self.reportable.len() > 0 {
            let _ = writeln!(writer, "OddDisconnectionsRule report:");
            for (ts, message) in self.reportable.iter() {
                let _ = writeln!(writer, "[{:?}] {}", ts, message);
            }
        }
    }

    fn report_signals(&self) -> &[Signal] {
        self.signals.as_slice()
    }
}

// What state are we in for the LinkKeyMismatchRule state?
#[derive(Debug, PartialEq)]
enum LinkKeyMismatchState {
    Requested, // Controller requested link key to the host
    Replied,   // Host replied the link key
}

/// Identifies instances when the peer forgets the link key or it mismatches with ours.
struct LinkKeyMismatchRule {
    /// Addresses in authenticating process
    states: HashMap<Address, LinkKeyMismatchState>,

    /// Active handles
    handles: HashMap<ConnectionHandle, Address>,

    /// Pre-defined signals discovered in the logs.
    signals: Vec<Signal>,

    /// Interesting occurrences surfaced by this rule.
    reportable: Vec<(NaiveDateTime, String)>,
}

impl LinkKeyMismatchRule {
    pub fn new() -> Self {
        LinkKeyMismatchRule {
            states: HashMap::new(),
            handles: HashMap::new(),
            signals: vec![],
            reportable: vec![],
        }
    }

    fn report_address_auth_failure(&mut self, address: &Address, packet: &Packet) {
        if let Some(LinkKeyMismatchState::Replied) = self.states.get(address) {
            self.signals.push(Signal {
                index: packet.index,
                ts: packet.ts.clone(),
                tag: ConnectionSignal::LinkKeyMismatch.into(),
            });

            self.reportable.push((
                packet.ts,
                format!("Peer {} forgets the link key, or it mismatches with ours.", address),
            ));
        }
    }
}

impl Rule for LinkKeyMismatchRule {
    // Currently this is only for BREDR device.
    // TODO(apusaka): add LE when logs are available.
    fn process(&mut self, packet: &Packet) {
        match &packet.inner {
            PacketChild::HciEvent(ev) => match ev.specialize() {
                EventChild::ConnectionComplete(ev) => {
                    if ev.get_status() == ErrorCode::Success {
                        self.handles.insert(ev.get_connection_handle(), ev.get_bd_addr());
                    }
                }

                EventChild::LinkKeyRequest(ev) => {
                    self.states.insert(ev.get_bd_addr(), LinkKeyMismatchState::Requested);
                }

                EventChild::SimplePairingComplete(ev) => {
                    if ev.get_status() == ErrorCode::AuthenticationFailure {
                        self.report_address_auth_failure(&ev.get_bd_addr(), &packet);
                    }

                    self.states.remove(&ev.get_bd_addr());
                }

                EventChild::AuthenticationComplete(ev) => {
                    if let Some(address) = self.handles.get(&ev.get_connection_handle()) {
                        let address = address.clone();
                        if ev.get_status() == ErrorCode::AuthenticationFailure {
                            self.report_address_auth_failure(&address, &packet);
                        }
                        self.states.remove(&address);
                    }
                }

                EventChild::DisconnectionComplete(ev) => {
                    if let Some(address) = self.handles.get(&ev.get_connection_handle()) {
                        let address = address.clone();
                        if ev.get_status() == ErrorCode::AuthenticationFailure {
                            self.report_address_auth_failure(&address, &packet);
                        }
                        self.states.remove(&address);
                    }

                    self.handles.remove(&ev.get_connection_handle());
                }

                // PacketChild::HciEvent(ev).specialize()
                _ => {}
            },

            PacketChild::HciCommand(cmd) => match cmd.specialize() {
                CommandChild::AclCommand(cmd) => match cmd.specialize() {
                    AclCommandChild::Disconnect(cmd) => {
                        // If reason is power off, the host might not wait for connection complete event
                        if cmd.get_reason()
                            == DisconnectReason::RemoteDeviceTerminatedConnectionPowerOff
                        {
                            if let Some(address) = self.handles.remove(&cmd.get_connection_handle())
                            {
                                self.states.remove(&address);
                            }
                        }
                    }

                    // CommandChild::AclCommand(cmd).specialize()
                    _ => {}
                },

                CommandChild::SecurityCommand(cmd) => match cmd.specialize() {
                    SecurityCommandChild::LinkKeyRequestReply(cmd) => {
                        let address = cmd.get_bd_addr();
                        if let Some(LinkKeyMismatchState::Requested) = self.states.get(&address) {
                            self.states.insert(address, LinkKeyMismatchState::Replied);
                        }
                    }

                    SecurityCommandChild::LinkKeyRequestNegativeReply(cmd) => {
                        self.states.remove(&cmd.get_bd_addr());
                    }

                    // CommandChild::SecurityCommand(cmd).specialize()
                    _ => {}
                },

                CommandChild::Reset(_) => {
                    self.states.clear();
                    self.handles.clear();
                }

                // PacketChild::HciCommand(cmd).specialize()
                _ => {}
            },

            // packet.inner
            _ => {}
        }
    }

    fn report(&self, writer: &mut dyn Write) {
        if self.reportable.len() > 0 {
            let _ = writeln!(writer, "LinkKeyMismatchRule report:");
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
pub fn get_connections_group() -> RuleGroup {
    let mut group = RuleGroup::new();
    group.add_rule(Box::new(LinkKeyMismatchRule::new()));
    group.add_rule(Box::new(OddDisconnectionsRule::new()));

    group
}
