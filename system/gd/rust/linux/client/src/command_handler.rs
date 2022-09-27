use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result};
use std::sync::{Arc, Mutex};

use crate::callbacks::BtGattCallback;
use crate::ClientContext;
use crate::{console_red, console_yellow, print_error, print_info};
use bt_topshim::btif::{BtConnectionState, BtStatus, BtTransport};
use bt_topshim::profiles::gatt::LePhy;
use btstack::bluetooth::{BluetoothDevice, IBluetooth, IBluetoothQA};
use btstack::bluetooth_adv::{AdvertiseData, AdvertisingSetParameters};
use btstack::bluetooth_gatt::{
    IBluetoothGatt, ScanFilter, ScanFilterCondition, ScanSettings, ScanType,
};
use btstack::socket_manager::{IBluetoothSocketManager, SocketResult};
use btstack::uuid::{Profile, UuidHelper, UuidWrapper};
use manager_service::iface_bluetooth_manager::IBluetoothManager;

const INDENT_CHAR: &str = " ";
const BAR1_CHAR: &str = "=";
const BAR2_CHAR: &str = "-";
const MAX_MENU_CHAR_WIDTH: usize = 72;
const GATT_CLIENT_APP_UUID: &str = "12345678123456781234567812345678";

type CommandFunction = fn(&mut CommandHandler, &Vec<String>);

fn _noop(_handler: &mut CommandHandler, _args: &Vec<String>) {
    // Used so we can add options with no direct function
    // e.g. help and quit
}

pub struct CommandOption {
    rules: Vec<String>,
    description: String,
    function_pointer: CommandFunction,
}

/// Handles string command entered from command line.
pub(crate) struct CommandHandler {
    context: Arc<Mutex<ClientContext>>,
    command_options: HashMap<String, CommandOption>,
}

struct DisplayList<T>(Vec<T>);

impl<T: Display> Display for DisplayList<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let _ = write!(f, "[\n");
        for item in self.0.iter() {
            let _ = write!(f, "  {}\n", item);
        }

        write!(f, "]")
    }
}

fn enforce_arg_len<F>(args: &Vec<String>, min_len: usize, msg: &str, mut action: F)
where
    F: FnMut(),
{
    if args.len() < min_len {
        println!("Usage: {}", msg);
    } else {
        action();
    }
}

fn wrap_help_text(text: &str, max: usize, indent: usize) -> String {
    let remaining_count = std::cmp::max(
        // real_max
        std::cmp::max(max, text.chars().count())
        // take away char count
         - text.chars().count()
        // take away real_indent
         - (
             if std::cmp::max(max, text.chars().count())- text.chars().count() > indent {
                 indent
             } else {
                 0
             }),
        0,
    );

    format!("|{}{}{}|", INDENT_CHAR.repeat(indent), text, INDENT_CHAR.repeat(remaining_count))
}

// This should be called during the constructor in order to populate the command option map
fn build_commands() -> HashMap<String, CommandOption> {
    let mut command_options = HashMap::<String, CommandOption>::new();
    command_options.insert(
        String::from("adapter"),
        CommandOption {
            rules: vec![String::from(
                "adapter <enable|disable|show|discoverable|connectable|set-name>",
            )],
            description: String::from(
                "Enable/Disable/Show default bluetooth adapter. (e.g. adapter enable)\n
                 Discoverable On/Off (e.g. adapter discoverable on)\n
                 Connectable On/Off (e.g. adapter connectable on)",
            ),
            function_pointer: CommandHandler::cmd_adapter,
        },
    );
    command_options.insert(
        String::from("bond"),
        CommandOption {
            rules: vec![String::from("bond <add|remove|cancel> <address>")],
            description: String::from("Creates a bond with a device."),
            function_pointer: CommandHandler::cmd_bond,
        },
    );
    command_options.insert(
        String::from("device"),
        CommandOption {
            rules: vec![String::from("device <connect|disconnect|info|set-alias> <address>")],
            description: String::from("Take action on a remote device. (i.e. info)"),
            function_pointer: CommandHandler::cmd_device,
        },
    );
    command_options.insert(
        String::from("discovery"),
        CommandOption {
            rules: vec![String::from("discovery <start|stop>")],
            description: String::from("Start and stop device discovery. (e.g. discovery start)"),
            function_pointer: CommandHandler::cmd_discovery,
        },
    );
    command_options.insert(
        String::from("floss"),
        CommandOption {
            rules: vec![String::from("floss <enable|disable>")],
            description: String::from("Enable or disable Floss for dogfood."),
            function_pointer: CommandHandler::cmd_floss,
        },
    );
    command_options.insert(
        String::from("gatt"),
        CommandOption {
            rules: vec![
                String::from("gatt register-client"),
                String::from("gatt client-connect <address>"),
                String::from("gatt client-read-phy <address>"),
                String::from("gatt client-discover-services <address>"),
                String::from("gatt client-disconnect <address>"),
                String::from("gatt configure-mtu <address> <mtu>"),
            ],
            description: String::from("GATT tools"),
            function_pointer: CommandHandler::cmd_gatt,
        },
    );
    command_options.insert(
        String::from("le-scan"),
        CommandOption {
            rules: vec![
                String::from("le-scan register-scanner"),
                String::from("le-scan unregister-scanner <scanner-id>"),
                String::from("le-scan start-scan <scanner-id>"),
                String::from("le-scan stop-scan <scanner-id>"),
            ],
            description: String::from("LE scanning utilities."),
            function_pointer: CommandHandler::cmd_le_scan,
        },
    );
    command_options.insert(
        String::from("advertise"),
        CommandOption {
            rules: vec![String::from("advertise <on|off>")],
            description: String::from("Advertising utilities."),
            function_pointer: CommandHandler::cmd_advertise,
        },
    );
    command_options.insert(
        String::from("socket"),
        CommandOption {
            rules: vec![String::from("socket test")],
            description: String::from("Socket manager utilities."),
            function_pointer: CommandHandler::cmd_socket,
        },
    );
    command_options.insert(
        String::from("get-address"),
        CommandOption {
            rules: vec![String::from("get-address")],
            description: String::from("Gets the local device address."),
            function_pointer: CommandHandler::cmd_get_address,
        },
    );
    command_options.insert(
        String::from("help"),
        CommandOption {
            rules: vec![String::from("help")],
            description: String::from("Shows this menu."),
            function_pointer: CommandHandler::cmd_help,
        },
    );
    command_options.insert(
        String::from("list"),
        CommandOption {
            rules: vec![String::from("list <bonded|found|connected>")],
            description: String::from(
                "List bonded or found remote devices. Use: list <bonded|found>",
            ),
            function_pointer: CommandHandler::cmd_list_devices,
        },
    );
    command_options.insert(
        String::from("quit"),
        CommandOption {
            rules: vec![String::from("quit")],
            description: String::from("Quit out of the interactive shell."),
            function_pointer: _noop,
        },
    );
    command_options
}

impl CommandHandler {
    /// Creates a new CommandHandler.
    pub fn new(context: Arc<Mutex<ClientContext>>) -> CommandHandler {
        CommandHandler { context, command_options: build_commands() }
    }

    /// Entry point for command and arguments
    pub fn process_cmd_line(&mut self, command: &String, args: &Vec<String>) {
        // Ignore empty line
        match &command[0..] {
            "" => {}
            _ => match self.command_options.get(command) {
                Some(cmd) => (cmd.function_pointer)(self, &args),
                None => {
                    println!("'{}' is an invalid command!", command);
                    self.cmd_help(&args);
                }
            },
        };
    }

    //  Common message for when the adapter isn't ready
    fn adapter_not_ready(&self) {
        let adapter_idx = self.context.lock().unwrap().default_adapter;
        print_error!(
            "Default adapter {} is not enabled. Enable the adapter before using this command.",
            adapter_idx
        );
    }

    fn cmd_help(&mut self, args: &Vec<String>) {
        if args.len() > 0 {
            match self.command_options.get(&args[0]) {
                Some(cmd) => {
                    println!(
                        "\n{}{}\n{}{}\n",
                        INDENT_CHAR.repeat(4),
                        args[0],
                        INDENT_CHAR.repeat(8),
                        cmd.description
                    );
                }
                None => {
                    println!("'{}' is an invalid command!", args[0]);
                    self.cmd_help(&vec![]);
                }
            }
        } else {
            // Build equals bar and Shave off sides
            let equal_bar = format!(" {} ", BAR1_CHAR.repeat(MAX_MENU_CHAR_WIDTH));

            // Build empty bar and Shave off sides
            let empty_bar = format!("|{}|", INDENT_CHAR.repeat(MAX_MENU_CHAR_WIDTH));

            // Header
            println!(
                "\n{}\n{}\n{}\n{}",
                equal_bar,
                wrap_help_text("Help Menu", MAX_MENU_CHAR_WIDTH, 2),
                // Minus bar
                format!("+{}+", BAR2_CHAR.repeat(MAX_MENU_CHAR_WIDTH)),
                empty_bar
            );

            // Print commands
            for (key, val) in self.command_options.iter() {
                println!(
                    "{}\n{}\n{}",
                    wrap_help_text(&key, MAX_MENU_CHAR_WIDTH, 4),
                    wrap_help_text(&val.description, MAX_MENU_CHAR_WIDTH, 8),
                    empty_bar
                );
            }

            // Footer
            println!("{}\n{}", empty_bar, equal_bar);
        }
    }

    fn cmd_adapter(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().manager_dbus.get_floss_enabled() {
            println!("Floss is not enabled. First run, `floss enable`");
            return;
        }

        let default_adapter = self.context.lock().unwrap().default_adapter;
        enforce_arg_len(
            args,
            1,
            "adapter <enable|disable|show|discoverable|connectable|set-name>",
            || match &args[0][0..] {
                "enable" => {
                    self.context.lock().unwrap().manager_dbus.start(default_adapter);
                }
                "disable" => {
                    self.context.lock().unwrap().manager_dbus.stop(default_adapter);
                }
                "show" => {
                    if !self.context.lock().unwrap().adapter_ready {
                        self.adapter_not_ready();
                        return;
                    }

                    let enabled = self.context.lock().unwrap().enabled;
                    let address = match self.context.lock().unwrap().adapter_address.as_ref() {
                        Some(x) => x.clone(),
                        None => String::from(""),
                    };
                    let context = self.context.lock().unwrap();
                    let adapter_dbus = context.adapter_dbus.as_ref().unwrap();
                    let qa_dbus = context.qa_dbus.as_ref().unwrap();
                    let name = adapter_dbus.get_name();
                    let uuids = adapter_dbus.get_uuids();
                    let is_discoverable = adapter_dbus.get_discoverable();
                    let is_connectable = qa_dbus.get_connectable();
                    let discoverable_timeout = adapter_dbus.get_discoverable_timeout();
                    let cod = adapter_dbus.get_bluetooth_class();
                    let multi_adv_supported = adapter_dbus.is_multi_advertisement_supported();
                    let le_ext_adv_supported = adapter_dbus.is_le_extended_advertising_supported();
                    let wbs_supported = adapter_dbus.is_wbs_supported();
                    let uuid_helper = UuidHelper::new();
                    let enabled_profiles = uuid_helper.get_enabled_profiles();
                    let connected_profiles: Vec<Profile> = enabled_profiles
                        .iter()
                        .filter(|&&prof| adapter_dbus.get_profile_connection_state(prof) > 0)
                        .cloned()
                        .collect();
                    print_info!("Address: {}", address);
                    print_info!("Name: {}", name);
                    print_info!("State: {}", if enabled { "enabled" } else { "disabled" });
                    print_info!("Discoverable: {}", is_discoverable);
                    print_info!("DiscoverableTimeout: {}s", discoverable_timeout);
                    print_info!("Connectable: {}", is_connectable);
                    print_info!("Class: {:#06x}", cod);
                    print_info!("IsMultiAdvertisementSupported: {}", multi_adv_supported);
                    print_info!("IsLeExtendedAdvertisingSupported: {}", le_ext_adv_supported);
                    print_info!("Connected profiles: {:?}", connected_profiles);
                    print_info!("IsWbsSupported: {}", wbs_supported);
                    print_info!(
                        "Uuids: {}",
                        DisplayList(
                            uuids
                                .iter()
                                .map(|&x| uuid_helper.known_uuid_to_string(&x))
                                .collect::<Vec<String>>()
                        )
                    );
                }
                "discoverable" => match &args[1][0..] {
                    "on" => {
                        let discoverable = self
                            .context
                            .lock()
                            .unwrap()
                            .adapter_dbus
                            .as_mut()
                            .unwrap()
                            .set_discoverable(true, 60);
                        print_info!(
                            "Set discoverable for 60s: {}",
                            if discoverable { "succeeded" } else { "failed" }
                        );
                    }
                    "off" => {
                        let discoverable = self
                            .context
                            .lock()
                            .unwrap()
                            .adapter_dbus
                            .as_mut()
                            .unwrap()
                            .set_discoverable(false, 60);
                        print_info!(
                            "Turn discoverable off: {}",
                            if discoverable { "succeeded" } else { "failed" }
                        );
                    }
                    _ => println!("Invalid argument for adapter discoverable '{}'", args[1]),
                },
                "connectable" => match &args[1][0..] {
                    "on" => {
                        let ret = self
                            .context
                            .lock()
                            .unwrap()
                            .qa_dbus
                            .as_mut()
                            .unwrap()
                            .set_connectable(true);
                        print_info!(
                            "Set connectable on {}",
                            if ret { "succeeded" } else { "failed" }
                        );
                    }
                    "off" => {
                        let ret = self
                            .context
                            .lock()
                            .unwrap()
                            .qa_dbus
                            .as_mut()
                            .unwrap()
                            .set_connectable(false);
                        print_info!(
                            "Set connectable off {}",
                            if ret { "succeeded" } else { "failed" }
                        );
                    }
                    _ => println!("Invalid argument for adapter connectable '{}'", args[1]),
                },
                "set-name" => {
                    if let Some(name) = args.get(1) {
                        self.context
                            .lock()
                            .unwrap()
                            .adapter_dbus
                            .as_ref()
                            .unwrap()
                            .set_name(name.to_string());
                    } else {
                        println!("usage: adapter set-name <name>");
                    }
                }

                _ => {
                    println!("Invalid argument '{}'", args[0]);
                }
            },
        );
    }

    fn cmd_get_address(&mut self, _args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        let address = self.context.lock().unwrap().update_adapter_address();
        print_info!("Local address = {}", &address);
    }

    fn cmd_discovery(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        enforce_arg_len(args, 1, "discovery <start|stop>", || match &args[0][0..] {
            "start" => {
                self.context.lock().unwrap().adapter_dbus.as_ref().unwrap().start_discovery();
            }
            "stop" => {
                self.context.lock().unwrap().adapter_dbus.as_ref().unwrap().cancel_discovery();
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    fn cmd_bond(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        enforce_arg_len(args, 2, "bond <add|remove|cancel> <address>", || match &args[0][0..] {
            "add" => {
                let device = BluetoothDevice {
                    address: String::from(&args[1]),
                    name: String::from("Classic Device"),
                };

                let bonding_attempt =
                    &self.context.lock().unwrap().bonding_attempt.as_ref().cloned();

                if bonding_attempt.is_some() {
                    print_info!(
                        "Already bonding [{}]. Cancel bonding first.",
                        bonding_attempt.as_ref().unwrap().address,
                    );
                    return;
                }

                let success = self
                    .context
                    .lock()
                    .unwrap()
                    .adapter_dbus
                    .as_ref()
                    .unwrap()
                    .create_bond(device.clone(), BtTransport::Auto);

                if success {
                    self.context.lock().unwrap().bonding_attempt = Some(device);
                }
            }
            "remove" => {
                let device = BluetoothDevice {
                    address: String::from(&args[1]),
                    name: String::from("Classic Device"),
                };

                self.context.lock().unwrap().adapter_dbus.as_ref().unwrap().remove_bond(device);
            }
            "cancel" => {
                let device = BluetoothDevice {
                    address: String::from(&args[1]),
                    name: String::from("Classic Device"),
                };

                self.context
                    .lock()
                    .unwrap()
                    .adapter_dbus
                    .as_ref()
                    .unwrap()
                    .cancel_bond_process(device);
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    fn cmd_device(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        enforce_arg_len(args, 2, "device <connect|disconnect|info|set-alias> <address>", || {
            match &args[0][0..] {
                "connect" => {
                    let device = BluetoothDevice {
                        address: String::from(&args[1]),
                        name: String::from("Classic Device"),
                    };

                    let success = self
                        .context
                        .lock()
                        .unwrap()
                        .adapter_dbus
                        .as_mut()
                        .unwrap()
                        .connect_all_enabled_profiles(device.clone());

                    if success {
                        println!("Connecting to {}", &device.address);
                    } else {
                        println!("Can't connect to {}", &device.address);
                    }
                }
                "disconnect" => {
                    let device = BluetoothDevice {
                        address: String::from(&args[1]),
                        name: String::from("Classic Device"),
                    };

                    let success = self
                        .context
                        .lock()
                        .unwrap()
                        .adapter_dbus
                        .as_mut()
                        .unwrap()
                        .disconnect_all_enabled_profiles(device.clone());

                    if success {
                        println!("Disconnecting from {}", &device.address);
                    } else {
                        println!("Can't disconnect from {}", &device.address);
                    }
                }
                "info" => {
                    let device = BluetoothDevice {
                        address: String::from(&args[1]),
                        name: String::from("Classic Device"),
                    };

                    let (name, alias, device_type, class, bonded, connection_state, uuids) = {
                        let ctx = self.context.lock().unwrap();
                        let adapter = ctx.adapter_dbus.as_ref().unwrap();

                        let name = adapter.get_remote_name(device.clone());
                        let device_type = adapter.get_remote_type(device.clone());
                        let alias = adapter.get_remote_alias(device.clone());
                        let class = adapter.get_remote_class(device.clone());
                        let bonded = adapter.get_bond_state(device.clone());
                        let connection_state = match adapter.get_connection_state(device.clone()) {
                            BtConnectionState::NotConnected => "Not Connected",
                            BtConnectionState::ConnectedOnly => "Connected",
                            _ => "Connected and Paired",
                        };
                        let uuids = adapter.get_remote_uuids(device.clone());

                        (name, alias, device_type, class, bonded, connection_state, uuids)
                    };

                    let uuid_helper = UuidHelper::new();
                    print_info!("Address: {}", &device.address);
                    print_info!("Name: {}", name);
                    print_info!("Alias: {}", alias);
                    print_info!("Type: {:?}", device_type);
                    print_info!("Class: {}", class);
                    print_info!("Bond State: {:?}", bonded);
                    print_info!("Connection State: {}", connection_state);
                    print_info!(
                        "Uuids: {}",
                        DisplayList(
                            uuids
                                .iter()
                                .map(|&x| uuid_helper.known_uuid_to_string(&x))
                                .collect::<Vec<String>>()
                        )
                    );
                }
                "set-alias" => {
                    if args.len() < 4 {
                        println!("usage: device set-alias <address> <new-alias>");
                        return;
                    }
                    let new_alias = &args[2];
                    let device =
                        BluetoothDevice { address: String::from(&args[1]), name: String::from("") };
                    let old_alias = self
                        .context
                        .lock()
                        .unwrap()
                        .adapter_dbus
                        .as_ref()
                        .unwrap()
                        .get_remote_alias(device.clone());
                    println!("Updating alias for {}: {} -> {}", &args[1], old_alias, new_alias);
                    self.context
                        .lock()
                        .unwrap()
                        .adapter_dbus
                        .as_mut()
                        .unwrap()
                        .set_remote_alias(device.clone(), new_alias.clone());
                }
                _ => {
                    println!("Invalid argument '{}'", args[0]);
                }
            }
        });
    }

    fn cmd_floss(&mut self, args: &Vec<String>) {
        enforce_arg_len(args, 1, "floss <enable|disable>", || match &args[0][0..] {
            "enable" => {
                self.context.lock().unwrap().manager_dbus.set_floss_enabled(true);
            }
            "disable" => {
                self.context.lock().unwrap().manager_dbus.set_floss_enabled(false);
            }
            "show" => {
                print_info!(
                    "Floss enabled: {}",
                    self.context.lock().unwrap().manager_dbus.get_floss_enabled()
                );
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    fn cmd_gatt(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        enforce_arg_len(args, 1, "gatt <commands>", || match &args[0][0..] {
            "register-client" => {
                let dbus_connection = self.context.lock().unwrap().dbus_connection.clone();
                let dbus_crossroads = self.context.lock().unwrap().dbus_crossroads.clone();

                self.context.lock().unwrap().gatt_dbus.as_mut().unwrap().register_client(
                    String::from(GATT_CLIENT_APP_UUID),
                    Box::new(BtGattCallback::new(
                        String::from("/org/chromium/bluetooth/client/bluetooth_gatt_callback"),
                        self.context.clone(),
                        dbus_connection,
                        dbus_crossroads,
                    )),
                    false,
                );
            }
            "client-connect" => {
                if args.len() < 2 {
                    println!("usage: gatt client-connect <addr>");
                    return;
                }

                let client_id = self.context.lock().unwrap().gatt_client_id;
                if client_id.is_none() {
                    println!("GATT client is not yet registered.");
                    return;
                }

                let addr = String::from(&args[1]);
                self.context.lock().unwrap().gatt_dbus.as_ref().unwrap().client_connect(
                    client_id.unwrap(),
                    addr,
                    false,
                    BtTransport::Le,
                    false,
                    LePhy::Phy1m,
                );
            }
            "client-disconnect" => {
                if args.len() < 2 {
                    println!("usage: gatt client-disconnect <addr>");
                    return;
                }

                let client_id = self.context.lock().unwrap().gatt_client_id;
                if client_id.is_none() {
                    println!("GATT client is not yet registered.");
                    return;
                }

                let addr = String::from(&args[1]);
                self.context
                    .lock()
                    .unwrap()
                    .gatt_dbus
                    .as_ref()
                    .unwrap()
                    .client_disconnect(client_id.unwrap(), addr);
            }
            "client-read-phy" => {
                if args.len() < 2 {
                    println!("usage: gatt client-read-phy <addr>");
                    return;
                }

                let client_id = self.context.lock().unwrap().gatt_client_id;
                if client_id.is_none() {
                    println!("GATT client is not yet registered.");
                    return;
                }

                let addr = String::from(&args[1]);
                self.context
                    .lock()
                    .unwrap()
                    .gatt_dbus
                    .as_mut()
                    .unwrap()
                    .client_read_phy(client_id.unwrap(), addr);
            }
            "client-discover-services" => {
                if args.len() < 2 {
                    println!("usage: gatt client-discover-services <addr>");
                    return;
                }

                let client_id = self.context.lock().unwrap().gatt_client_id;
                if client_id.is_none() {
                    println!("GATT client is not yet registered.");
                    return;
                }

                let addr = String::from(&args[1]);
                self.context
                    .lock()
                    .unwrap()
                    .gatt_dbus
                    .as_ref()
                    .unwrap()
                    .discover_services(client_id.unwrap(), addr);
            }
            "configure-mtu" => {
                if args.len() < 3 {
                    println!("usage: gatt configure-mtu <addr> <mtu>");
                    return;
                }

                let client_id = self.context.lock().unwrap().gatt_client_id;
                if client_id.is_none() {
                    println!("GATT client is not yet registered.");
                    return;
                }

                let addr = String::from(&args[1]);
                let mtu = String::from(&args[2]).parse::<i32>();
                if let Ok(m) = mtu {
                    self.context.lock().unwrap().gatt_dbus.as_ref().unwrap().configure_mtu(
                        client_id.unwrap(),
                        addr,
                        m,
                    );
                } else {
                    print_error!("Failed parsing mtu");
                }
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    fn cmd_le_scan(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        enforce_arg_len(args, 1, "le-scan <commands>", || match &args[0][0..] {
            "register-scanner" => {
                let scanner_callback_id = self.context.lock().unwrap().scanner_callback_id;
                if let Some(id) = scanner_callback_id {
                    let uuid = self
                        .context
                        .lock()
                        .unwrap()
                        .gatt_dbus
                        .as_mut()
                        .unwrap()
                        .register_scanner(id);
                    print_info!("Scanner to be registered with UUID = {}", UuidWrapper(&uuid));
                } else {
                    print_error!("Cannot register scanner before registering scanner callback");
                }
            }
            "unregister-scanner" => {
                if args.len() < 2 {
                    println!("usage: le-scan unregister-scanner <scanner-id>");
                    return;
                }

                let scanner_id = String::from(&args[1]).parse::<u8>();

                if let Ok(id) = scanner_id {
                    self.context.lock().unwrap().gatt_dbus.as_mut().unwrap().unregister_scanner(id);
                } else {
                    print_error!("Failed parsing scanner id");
                }
            }
            "start-scan" => {
                if args.len() < 2 {
                    println!("usage: le-scan start-scan <scanner-id>");
                    return;
                }

                let scanner_id = String::from(&args[1]).parse::<u8>();

                if let Ok(id) = scanner_id {
                    self.context.lock().unwrap().gatt_dbus.as_mut().unwrap().start_scan(
                        id,
                        // TODO(b/217274432): Construct real settings and filters.
                        ScanSettings { interval: 0, window: 0, scan_type: ScanType::Active },
                        ScanFilter {
                            condition: ScanFilterCondition::Patterns(vec![]),
                            rssi_low_threshold: 0,
                            rssi_low_timeout: 0,
                            rssi_high_threshold: 0,
                            rssi_sampling_period: 0,
                        },
                    );
                    self.context.lock().unwrap().active_scanner_ids.insert(id);
                } else {
                    print_error!("Failed parsing scanner id");
                }
            }
            "stop-scan" => {
                if args.len() < 2 {
                    println!("usage: le-scan stop-scan <scanner-id>");
                    return;
                }

                let scanner_id = String::from(&args[1]).parse::<u8>();

                if let Ok(id) = scanner_id {
                    self.context.lock().unwrap().gatt_dbus.as_mut().unwrap().stop_scan(id);
                    self.context.lock().unwrap().active_scanner_ids.remove(&id);
                } else {
                    print_error!("Failed parsing scanner id");
                }
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    // TODO(b/233128828): More options will be implemented to test BLE advertising.
    // Such as setting advertising parameters, starting multiple advertising sets, etc.
    fn cmd_advertise(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }
        if self.context.lock().unwrap().advertiser_callback_id == None {
            return;
        }
        let callback_id = self.context.lock().unwrap().advertiser_callback_id.clone().unwrap();

        enforce_arg_len(args, 1, "advertise <commands>", || match &args[0][0..] {
            "on" => {
                if self.context.lock().unwrap().adv_sets.keys().len() > 0 {
                    print_error!("Already started advertising");
                    return;
                }

                let params = AdvertisingSetParameters {
                    connectable: false,
                    scannable: false,
                    is_legacy: true,
                    is_anonymous: false,
                    include_tx_power: true,
                    primary_phy: LePhy::Phy1m,
                    secondary_phy: LePhy::Phy1m,
                    interval: 160,
                    tx_power_level: -21,
                    own_address_type: 0, // random
                };

                let data = AdvertiseData {
                    service_uuids: Vec::<String>::new(),
                    solicit_uuids: Vec::<String>::new(),
                    transport_discovery_data: Vec::<Vec<u8>>::new(),
                    manufacturer_data: HashMap::<i32, Vec<u8>>::from([(0, vec![0, 1, 2])]),
                    service_data: HashMap::<String, Vec<u8>>::new(),
                    include_tx_power_level: true,
                    include_device_name: true,
                };

                let reg_id = self
                    .context
                    .lock()
                    .unwrap()
                    .gatt_dbus
                    .as_mut()
                    .unwrap()
                    .start_advertising_set(params, data, None, None, None, 0, 0, callback_id);
                print_info!("Starting advertising set for reg_id = {}", reg_id);
            }
            "off" => {
                let adv_sets = self.context.lock().unwrap().adv_sets.clone();
                for (_, val) in adv_sets.iter() {
                    if let Some(&adv_id) = val.as_ref() {
                        print_info!("Stopping advertising set {}", adv_id);
                        self.context
                            .lock()
                            .unwrap()
                            .gatt_dbus
                            .as_mut()
                            .unwrap()
                            .stop_advertising_set(adv_id);
                    }
                }
                self.context.lock().unwrap().adv_sets.clear();
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    fn cmd_socket(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }
        let callback_id = match self.context.lock().unwrap().socket_manager_callback_id.clone() {
            Some(id) => id,
            None => {
                return;
            }
        };

        enforce_arg_len(args, 1, "socket <test>", || match &args[0][0..] {
            "test" => {
                let SocketResult { status, id } = self
                    .context
                    .lock()
                    .unwrap()
                    .socket_manager_dbus
                    .as_mut()
                    .unwrap()
                    .listen_using_l2cap_channel(callback_id);

                if status != BtStatus::Success {
                    print_error!(
                        "Failed to request for listening using l2cap channel, status = {:?}",
                        status,
                    );
                    return;
                }
                print_info!("Requested for listening using l2cap channel on socket {}", id);
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }

    /// Get the list of rules of supported commands
    pub fn get_command_rule_list(&self) -> Vec<String> {
        self.command_options.values().flat_map(|cmd| cmd.rules.clone()).collect()
    }

    fn cmd_list_devices(&mut self, args: &Vec<String>) {
        if !self.context.lock().unwrap().adapter_ready {
            self.adapter_not_ready();
            return;
        }

        enforce_arg_len(args, 1, "list <bonded|found|connected>", || match &args[0][0..] {
            "bonded" => {
                print_info!("Known bonded devices:");
                let devices = self
                    .context
                    .lock()
                    .unwrap()
                    .adapter_dbus
                    .as_ref()
                    .unwrap()
                    .get_bonded_devices();
                for device in devices.iter() {
                    print_info!("[{:17}] {}", device.address, device.name);
                }
            }
            "found" => {
                print_info!("Devices found in most recent discovery session:");
                for (key, val) in self.context.lock().unwrap().found_devices.iter() {
                    print_info!("[{:17}] {}", key, val.name);
                }
            }
            "connected" => {
                print_info!("Connected devices:");
                let devices = self
                    .context
                    .lock()
                    .unwrap()
                    .adapter_dbus
                    .as_ref()
                    .unwrap()
                    .get_connected_devices();
                for device in devices.iter() {
                    print_info!("[{:17}] {}", device.address, device.name);
                }
            }
            _ => {
                println!("Invalid argument '{}'", args[0]);
            }
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_wrap_help_text() {
        let text = "hello";
        let text_len = text.chars().count();
        // ensure no overflow
        assert_eq!(format!("|{}|", text), wrap_help_text(text, 4, 0));
        assert_eq!(format!("|{}|", text), wrap_help_text(text, 5, 0));
        assert_eq!(format!("|{}{}|", text, " "), wrap_help_text(text, 6, 0));
        assert_eq!(format!("|{}{}|", text, " ".repeat(2)), wrap_help_text(text, 7, 0));
        assert_eq!(
            format!("|{}{}|", text, " ".repeat(100 - text_len)),
            wrap_help_text(text, 100, 0)
        );
        assert_eq!(format!("|{}{}|", " ", text), wrap_help_text(text, 4, 1));
        assert_eq!(format!("|{}{}|", " ".repeat(2), text), wrap_help_text(text, 5, 2));
        assert_eq!(format!("|{}{}{}|", " ".repeat(3), text, " "), wrap_help_text(text, 6, 3));
        assert_eq!(
            format!("|{}{}{}|", " ".repeat(4), text, " ".repeat(7 - text_len)),
            wrap_help_text(text, 7, 4)
        );
        assert_eq!(format!("|{}{}|", " ".repeat(9), text), wrap_help_text(text, 4, 9));
        assert_eq!(format!("|{}{}|", " ".repeat(10), text), wrap_help_text(text, 3, 10));
        assert_eq!(format!("|{}{}|", " ".repeat(11), text), wrap_help_text(text, 2, 11));
        assert_eq!(format!("|{}{}|", " ".repeat(12), text), wrap_help_text(text, 1, 12));
        assert_eq!("||", wrap_help_text("", 0, 0));
        assert_eq!("| |", wrap_help_text("", 1, 0));
        assert_eq!("|  |", wrap_help_text("", 1, 1));
        assert_eq!("| |", wrap_help_text("", 0, 1));
    }

    #[test]
    fn test_enforce_arg_len() {
        // With min arg set and min arg supplied
        let args: &Vec<String> = &vec![String::from("arg")];
        let mut i: usize = 0;
        enforce_arg_len(args, 1, "help text", || {
            i = 1;
        });
        assert_eq!(1, i);

        // With no min arg set and with arg supplied
        i = 0;
        enforce_arg_len(args, 0, "help text", || {
            i = 1;
        });
        assert_eq!(1, i);

        // With min arg set and no min arg supplied
        let args: &Vec<String> = &vec![];
        i = 0;
        enforce_arg_len(args, 1, "help text", || {
            i = 1;
        });
        assert_eq!(0, i);

        // With no min arg set and no arg supplied
        i = 0;
        enforce_arg_len(args, 0, "help text", || {
            i = 1;
        });
        assert_eq!(1, i);
    }
}
