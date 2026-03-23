fn main() {
    let args: Vec<String> = std::env::args().collect();

    let get_arg = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let keys_path  = get_arg("--keys").unwrap_or_else(|| "keys.json".to_string());
    let data_dir   = get_arg("--data-dir").unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr   = get_arg("--p2p-addr").unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let bootstrap  = get_arg("--bootstrap-peers").unwrap_or_default();

    println!("╔══════════════════════════════════════╗");
    println!("║         INDRA v2 Node Starting        ║");
    println!("╚══════════════════════════════════════╝");
    println!("Keys:       {}", keys_path);
    println!("Data dir:   {}", data_dir);
    println!("P2P:        {}", p2p_addr);
    println!("Bootstrap:  {}", if bootstrap.is_empty() { "(none - I am bootstrap)" } else { &bootstrap });

    // Load keys from keys.json
    let keys_str = std::fs::read_to_string(&keys_path)
        .unwrap_or_else(|_| panic!("Cannot read keys file: {}", keys_path));

    let hybrid_seed = extract_hex_field(&keys_str, "hybrid_seed");
    let bls_seed    = extract_hex_field(&keys_str, "bls_seed");
    let vrf_seed    = extract_hex_field(&keys_str, "vrf_seed");

    let config = indra_node::NodeConfig {
        data_dir:          std::path::PathBuf::from(&data_dir),
        validator_seed:    Some(hybrid_seed),
        bls_seed:          Some(bls_seed),
        vrf_seed:          Some(vrf_seed),
        p2p_addr:          p2p_addr.clone(),
        bootstrap_peers:   if bootstrap.is_empty() { vec![] } else { vec![bootstrap] },
        snapshot_interval: 300,
        mempool_capacity:  5_000,
    };

    // Initialise node engine
    let engine = indra_node::NodeEngine::init(config)
        .unwrap_or_else(|e| panic!("Failed to init node: {}", e));

    let validator_id = engine.validator_id()
        .map(|id| hex::encode(id.0))
        .unwrap_or_else(|| "full node (no validator keys)".to_string());

    println!("\nValidator ID: {}", &validator_id[..16]);
    println!("Genesis height: {}", engine.height());
    println!("\nNode running. Status updates every 6 seconds.");
    println!("Press Ctrl+C to stop.\n");

    // Wrap in Arc<Mutex> for status loop
    let engine = std::sync::Arc::new(std::sync::Mutex::new(engine));

    // Status loop
    let mut tick = 0u64;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(6));
        tick += 1;
        let e = engine.lock().unwrap();
        println!(
            "[tick {}] height={} base_fee={} mempool={} txs",
            tick,
            e.state.height,
            e.state.base_fee,
            e.mempool.len(),
        );
    }
}

fn extract_hex_field(json: &str, field: &str) -> [u8; 32] {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)
        .unwrap_or_else(|| panic!("Field '{}' not found in keys.json", field));
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap() + 1;
    let end   = after[start..].find('"').unwrap() + start;
    let hex_str = &after[start..end];
    let bytes = hex::decode(hex_str)
        .unwrap_or_else(|_| panic!("Invalid hex for field '{}'", field));
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}
