fn main() {
    let args: Vec<String> = std::env::args().collect();
    let passphrase = args.iter()
        .position(|a| a == "--passphrase")
        .and_then(|i| args.get(i + 1))
        .expect("Usage: keygen --passphrase <phrase> --output <file>");
    let output = args.iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .expect("Usage: keygen --passphrase <phrase> --output <file>");
    let keys = indra_cli::generate_from_passphrase(passphrase).unwrap();
    let json = keys.to_json();
    std::fs::write(output, &json).unwrap();
    println!("Keys written to {}", output);
    println!("\nYour validator_id: {}", 
        json.lines().find(|l| l.contains("validator_id")).unwrap_or(""));
}
