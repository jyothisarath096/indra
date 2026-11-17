#![deny(unused_must_use)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Offline, new-directory-only recovery of a finalized sync prefix.

use std::path::PathBuf;

use indra_node::{recovery::recover_finalized_prefix, NodeConfig};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(source_dir) = args.next().map(PathBuf::from) else {
        usage_and_exit();
    };
    let Some(destination_dir) = args.next().map(PathBuf::from) else {
        usage_and_exit();
    };
    let Some(genesis_path) = args.next().map(PathBuf::from) else {
        usage_and_exit();
    };
    if args.next().is_some() {
        usage_and_exit();
    }

    let mut config = NodeConfig::full_node(destination_dir);
    config.genesis_path = Some(genesis_path.to_string_lossy().into_owned());
    config.bootstrap_peers.clear();
    match recover_finalized_prefix(&source_dir, config) {
        Ok(report) => {
            println!("recovered finalized height {}", report.recovered_height);
            if let Some(height) = report.first_unfinalized_height {
                println!("left uncertified source suffix beginning at height {height}");
            }
            println!("new data directory: {}", report.destination_dir.display());
        }
        Err(error) => {
            eprintln!("recovery failed safely: {error}");
            std::process::exit(1);
        }
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: indra-sync-recover <source-data-dir> <new-destination-dir> <trusted-genesis.toml>"
    );
    std::process::exit(2);
}
