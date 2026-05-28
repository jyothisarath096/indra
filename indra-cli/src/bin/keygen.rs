fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output = args.iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map_or("keys.json", String::as_str);
    let recover_phrase = args.iter()
        .position(|a| a == "--recover")
        .and_then(|i| args.get(i + 1));
    let passphrase = args.iter()
        .position(|a| a == "--passphrase")
        .and_then(|i| args.get(i + 1));

    let (mnemonic, keys) = if let Some(phrase) = recover_phrase {
        match indra_cli::recover_from_mnemonic(phrase) {
            Ok(keys) => (None, keys),
            Err(err) => {
                eprintln!("Mnemonic recovery failed: {}", err);
                std::process::exit(1);
            }
        }
    } else if let Some(phrase) = passphrase {
        match indra_cli::generate_from_passphrase(phrase) {
            Ok(keys) => (None, keys),
            Err(err) => {
                eprintln!("Passphrase key generation failed: {}", err);
                std::process::exit(1);
            }
        }
    } else {
        match indra_cli::generate_from_new_mnemonic() {
            Ok((phrase, keys)) => (Some(phrase), keys),
            Err(err) => {
                eprintln!("Mnemonic generation failed: {}", err);
                std::process::exit(1);
            }
        }
    };

    let json = keys.to_json();
    if let Err(err) = std::fs::write(output, &json) {
        eprintln!("Failed to write {}: {}", output, err);
        std::process::exit(1);
    }

    if let Some(phrase) = mnemonic {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        println!("═══════════════════════════════════════════════════════════");
        println!("  INDRA VALIDATOR KEYS GENERATED");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!("  YOUR 24-WORD RECOVERY PHRASE:");
        println!();
        for chunk in words.chunks(6) {
            println!("  {}", chunk.join(" "));
        }
        println!();
        println!("  WRITE THESE DOWN. STORE THEM SAFELY.");
        println!("  Anyone with these words can access your funds.");
        println!("  These words are NOT stored in keys.json.");
        println!("  If you lose keys.json, use these words to recover.");
        println!();
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    println!("  Validator ID:     {}", hex::encode(keys.public.validator_id));
    println!("  Classical PK:     {}", hex::encode(keys.public.hybrid_classical_pk));
    println!("  Keys written to:  {}", output);
}
