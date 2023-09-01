//
//  Copyright 2021 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    let packets_prebuilt = match env::var("HCI_PACKETS_PREBUILT") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from("hci_packets.rs"),
    };

    if Path::new(packets_prebuilt.as_os_str()).exists() {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let out_file = out_dir.join("hci_packets.rs");
        std::fs::copy(
            packets_prebuilt.as_os_str().to_str().unwrap(),
            out_file.as_os_str().to_str().unwrap(),
        )
        .unwrap();
    } else {
        generate_packets();
    }
}

fn generate_packets() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let pdl_root = match env::var("PLATFORM_SUBDIR") {
        Ok(dir) => PathBuf::from(dir).join("bt/pdl"),
        // Currently at //platform2/gd/rust/rust/packets
        Err(_) => {
            PathBuf::from(env::current_dir().unwrap()).join("../../../pdl").canonicalize().unwrap()
        }
    };

    let in_file = pdl_root.join("hci/hci_packets.pdl");
    let out_file = File::create(out_dir.join("hci_packets.rs")).unwrap();

    // Expect pdlc to be in the PATH
    println!("cargo:rerun-if-changed={}", in_file.display());
    let output = Command::new("pdlc")
        .arg("--output-format")
        .arg("rust")
        .arg(in_file)
        .stdout(Stdio::from(out_file))
        .output()
        .unwrap();

    println!(
        "Status: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(output.stderr.as_slice())
    );
}
