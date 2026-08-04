fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args
        .iter()
        .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        print_help();
        return;
    }
    if args.get(1).map(String::as_str) == Some("encrypt") {
        cmd_encrypt(&args[2..]);
        return;
    }
    if args.get(1).map(String::as_str) == Some("decrypt") {
        cmd_decrypt(&args[2..]);
        return;
    }
    if args.get(1).map(String::as_str) == Some("inspect") {
        cmd_inspect(&args[2..]);
        return;
    }
    if args.get(1).map(String::as_str) == Some("cold") {
        cmd_cold(&args[2..]);
        return;
    }

    let output = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map_or("keys.json", String::as_str);
    let chain_id = args
        .iter()
        .position(|a| a == "--chain-id")
        .and_then(|i| args.get(i + 1))
        .map_or(
            indra_core::types::primitives::DEFAULT_CHAIN_ID,
            String::as_str,
        );
    if indra_cli::has_secret_value_in_argv(&args, "--recover") {
        eprintln!("Error: do not pass a mnemonic in argv. Use '--recover' and enter it at the secure prompt.");
        std::process::exit(1);
    }
    if indra_cli::has_secret_value_in_argv(&args, "--passphrase") {
        eprintln!("Error: do not pass a passphrase in argv. Use '--passphrase' and enter it at the secure prompt.");
        std::process::exit(1);
    }
    let recover_mode = args.iter().any(|a| a == "--recover");
    let passphrase_mode = args.iter().any(|a| a == "--passphrase");
    if recover_mode && passphrase_mode {
        eprintln!("Error: choose either --recover or --passphrase, not both");
        std::process::exit(1);
    }
    let plaintext_unsafe = args.iter().any(|a| a == "--plaintext-unsafe");
    let password_source = keygen_password_source(&args);
    if !plaintext_unsafe
        && matches!(password_source, indra_cli::PasswordSource::Prompt)
        && !stdin_is_tty()
    {
        eprintln!(
            "Error: encrypted key generation in noninteractive mode requires --keys-password-file/--password-file, \
             or explicitly opt out with --plaintext-unsafe for test/dev use."
        );
        std::process::exit(1);
    }
    let name_arg = args
        .iter()
        .position(|a| a == "--name")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let name = name_arg.unwrap_or_else(|| {
        if recover_mode {
            String::new()
        } else {
            print!("  Enter your validator name: ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            input.trim().to_string()
        }
    });

    let (mnemonic, keys) = if recover_mode {
        let phrase = read_secret_from_stdin("Enter recovery phrase: ");
        match indra_cli::recover_from_mnemonic(&phrase, name.clone()) {
            Ok(keys) => (None, keys),
            Err(err) => {
                eprintln!("Mnemonic recovery failed: {}", err);
                std::process::exit(1);
            }
        }
    } else if passphrase_mode {
        let phrase = read_secret_from_stdin("Enter passphrase: ");
        let confirm = read_secret_from_stdin("Confirm passphrase: ");
        if phrase != confirm {
            eprintln!("Passphrases do not match");
            std::process::exit(1);
        }
        match indra_cli::generate_from_passphrase(&phrase, name.clone()) {
            Ok(keys) => (None, keys),
            Err(err) => {
                eprintln!("Passphrase key generation failed: {}", err);
                std::process::exit(1);
            }
        }
    } else {
        match indra_cli::generate_from_new_mnemonic(name.clone()) {
            Ok((phrase, keys)) => (Some(phrase), keys),
            Err(err) => {
                eprintln!("Mnemonic generation failed: {}", err);
                std::process::exit(1);
            }
        }
    };

    let json = if plaintext_unsafe {
        eprintln!(
            "WARNING: writing plaintext keys.json because --plaintext-unsafe was supplied. \
             Do not use plaintext key files for mainnet validators."
        );
        keys.to_json()
    } else {
        let password = password_source.resolve(true).unwrap_or_else(|e| {
            eprintln!("Failed to read keystore password: {}", e);
            std::process::exit(1);
        });
        indra_cli::encrypt_plaintext_keys(&keys, password.as_bytes()).unwrap_or_else(|e| {
            eprintln!("Failed to encrypt keys: {}", e);
            std::process::exit(1);
        })
    };
    if let Err(err) = indra_cli::write_keys_file_secure(output, &json) {
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

    println!("  Validator Name:   {}", keys.name);
    println!(
        "  Validator ID:     {}",
        hex::encode(keys.public.validator_id)
    );
    println!(
        "  Classical PK:     {}",
        hex::encode(keys.public.hybrid_classical_pk)
    );
    if let Some(payment_pubkey) = &keys.public.payment_pubkey {
        println!(
            "  Payment PK:       {}",
            hex::encode(payment_pubkey.encode())
        );
    }
    let payment_address = keys
        .payment_address(chain_id.as_bytes())
        .unwrap_or_else(|error| {
            eprintln!("Failed to construct canonical payment address: {error}");
            std::process::exit(1);
        });
    println!("  Payment Address:  {}", payment_address.to_text());
    println!("  Keys written to:  {}", output);
    if !plaintext_unsafe {
        println!("  Storage:          encrypted at rest");
        println!("  For unattended validator startup, store the password in a separate 0600 password file and set [keys].password_file.");
    }
}

fn cmd_encrypt(args: &[String]) {
    let keys_path = get(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let replace = args.iter().any(|a| a == "--replace");
    let out = get(args, "--out");
    if replace && out.is_some() {
        eprintln!("Error: choose either --replace or --out, not both");
        std::process::exit(1);
    }
    if !replace && out.is_none() {
        eprintln!("Error: encrypt requires --out <path> or --replace");
        std::process::exit(1);
    }
    let keys = indra_cli::KeysFile::load(&keys_path).unwrap_or_else(|e| {
        eprintln!("Failed to load plaintext keys: {}", e);
        std::process::exit(1);
    });
    let password = keygen_password_source_slice(args)
        .resolve(true)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read keystore password: {}", e);
            std::process::exit(1);
        });
    if replace {
        let backup = indra_cli::encrypt_plaintext_keys_replace(
            std::path::Path::new(&keys_path),
            &keys,
            password.as_bytes(),
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to encrypt/replace keys: {}", e);
            std::process::exit(1);
        });
        println!("Encrypted keys written to: {}", keys_path);
        println!("Plaintext backup retained at: {}", backup.display());
        println!("Verify the encrypted key works, then securely remove the plaintext backup.");
    } else {
        let encrypted = indra_cli::encrypt_plaintext_keys(&keys, password.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("Failed to encrypt keys: {}", e);
                std::process::exit(1);
            });
        let out = out.unwrap();
        indra_cli::write_keys_file_secure(&out, &encrypted).unwrap_or_else(|e| {
            eprintln!("Failed to write {}: {}", out, e);
            std::process::exit(1);
        });
        println!("Encrypted keys written to: {}", out);
    }
}

fn cmd_decrypt(args: &[String]) {
    let keys_path = get(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let out = get(args, "--out").unwrap_or_else(|| {
        eprintln!("Error: decrypt requires --out <path>; refusing to print private keys to stdout");
        std::process::exit(1);
    });
    let json = std::fs::read_to_string(&keys_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", keys_path, e);
        std::process::exit(1);
    });
    match indra_cli::inspect_key_file_public_metadata(&json) {
        Ok(indra_cli::KeyFilePublicMetadata::Hot { .. }) => {}
        Ok(indra_cli::KeyFilePublicMetadata::Cold { .. }) => {
            eprintln!(
                "Failed to decrypt keys: plaintext cold-key export is prohibited; use `cold split` \
                 for backup or `cold recover` to create an encrypted temporary cold keystore"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("Failed to parse keys: {error}");
            std::process::exit(1);
        }
    }
    let password = keygen_password_source_slice(args)
        .resolve(false)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read keystore password: {}", e);
            std::process::exit(1);
        });
    let keys = indra_cli::decrypt_encrypted_keys(&json, password.as_bytes()).unwrap_or_else(|e| {
        eprintln!("Failed to decrypt keys: {}", e);
        std::process::exit(1);
    });
    indra_cli::write_keys_file_secure(&out, &keys.to_json()).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {}", out, e);
        std::process::exit(1);
    });
    println!("Plaintext keys written to: {}", out);
    println!(
        "WARNING: this file contains private key material. Use only for emergency/debug workflows."
    );
}

fn cmd_inspect(args: &[String]) {
    let keys_path = get(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let json = std::fs::read_to_string(&keys_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let metadata = indra_cli::inspect_key_file_public_metadata(&json).unwrap_or_else(|e| {
        eprintln!("Failed to inspect keys: {}", e);
        std::process::exit(1);
    });
    match metadata {
        indra_cli::KeyFilePublicMetadata::Hot { name, public } => {
            println!("Validator Name: {}", name);
            println!("Validator ID:   {}", hex::encode(public.validator_id));
            println!(
                "Classical PK:   {}",
                hex::encode(public.hybrid_classical_pk)
            );
            println!("PQ PK bytes:    {}", public.hybrid_pq_pk.len());
            println!("VRF PK:         {}", hex::encode(public.vrf_pk));
            if let Some(payment_pubkey) = &public.payment_pubkey {
                println!("Payment PK:     {}", hex::encode(payment_pubkey.encode()));
            } else {
                println!("Payment PK:     <absent>");
            }
        }
        indra_cli::KeyFilePublicMetadata::Cold {
            classical_pk,
            pq_pk,
        } => {
            println!("Key Role:       validator cold authority");
            println!("Classical PK:   {}", hex::encode(classical_pk));
            println!("PQ PK:          {}", hex::encode(&pq_pk));
            println!("PQ PK bytes:    {}", pq_pk.len());
        }
    }
}

fn cmd_cold(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("ceremony") => return cmd_cold_ceremony(&args[1..]),
        Some("split") => return cmd_cold_split(&args[1..]),
        Some("verify") => return cmd_cold_verify(&args[1..]),
        Some("recover") => return cmd_cold_recover(&args[1..]),
        Some("reshare") => return cmd_cold_reshare(&args[1..]),
        _ => {}
    }
    let output = get(args, "--output").unwrap_or_else(|| "validator-cold-keys.json".to_string());
    let plaintext_unsafe = args.iter().any(|arg| arg == "--plaintext-unsafe");
    let force = args.iter().any(|arg| arg == "--force");
    let password = if plaintext_unsafe {
        eprintln!("WARNING: writing plaintext cold keys because --plaintext-unsafe was supplied.");
        None
    } else {
        Some(
            keygen_password_source_slice(args)
                .resolve(true)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to read cold-keystore password: {}", e);
                    std::process::exit(1);
                }),
        )
    };
    let keys = indra_cli::generate_cold_keys_file(
        std::path::Path::new(&output),
        password.as_ref().map(|value| value.as_bytes()),
        force,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to generate cold keys: {}", e);
        std::process::exit(1);
    });
    println!("INDRA validator cold key generated");
    println!("Output:       {}", output);
    println!("Classical PK: {}", hex::encode(keys.classical_pk));
    println!("PQ PK:        {}", hex::encode(keys.pq_pk));
    println!("Hot keys.json was not read or modified.");
}

fn cold_fail(message: impl std::fmt::Display) -> ! {
    eprintln!("Cold-key ceremony failed: {message}");
    std::process::exit(1)
}

fn required(args: &[String], flag: &str) -> String {
    get(args, flag).unwrap_or_else(|| cold_fail(format!("missing required flag {flag}")))
}

fn parse_u8_flag(args: &[String], flag: &str) -> u8 {
    required(args, flag)
        .parse::<u8>()
        .unwrap_or_else(|_| cold_fail(format!("{flag} must be an integer in 0..=255")))
}

fn parse_hex32_flag(args: &[String], flag: &str) -> [u8; 32] {
    let value = required(args, flag);
    let bytes = hex::decode(&value).unwrap_or_else(|_| cold_fail(format!("{flag} is invalid hex")));
    bytes
        .try_into()
        .unwrap_or_else(|_| cold_fail(format!("{flag} must contain exactly 32 bytes")))
}

fn share_paths(args: &[String]) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--share" {
            let path = args
                .get(index + 1)
                .unwrap_or_else(|| cold_fail("--share requires a path"));
            paths.push(std::path::PathBuf::from(path));
            index += 2;
        } else {
            index += 1;
        }
    }
    if paths.is_empty() {
        cold_fail("provide repeated --share <path> arguments");
    }
    paths
}

fn load_share_set(args: &[String]) -> Vec<indra_cli::ColdShareFile> {
    share_paths(args)
        .iter()
        .map(|path| indra_cli::read_cold_share(path).unwrap_or_else(|e| cold_fail(e)))
        .collect()
}

fn write_ceremony(ceremony: &indra_cli::ColdShareCeremony, out_dir: &std::path::Path, force: bool) {
    std::fs::create_dir_all(out_dir).unwrap_or_else(|e| cold_fail(e));
    let manifest_path = out_dir.join("ceremony.json");
    let share_paths: Vec<_> = ceremony
        .shares
        .iter()
        .map(|share| out_dir.join(format!("share-{:03}.json", share.share_index)))
        .collect();
    if !force {
        for path in std::iter::once(&manifest_path).chain(share_paths.iter()) {
            if path.exists() {
                cold_fail(format!("{} already exists", path.display()));
            }
        }
    }
    let manifest_json =
        serde_json::to_string_pretty(&ceremony.manifest).unwrap_or_else(|e| cold_fail(e));
    indra_cli::write_keys_file_secure(
        manifest_path
            .to_str()
            .unwrap_or_else(|| cold_fail("output path is not UTF-8")),
        &manifest_json,
    )
    .unwrap_or_else(|e| cold_fail(e));
    for (share, path) in ceremony.shares.iter().zip(share_paths) {
        indra_cli::write_cold_share_secure(&path, share, force).unwrap_or_else(|e| cold_fail(e));
    }
    println!(
        "Cold-key ceremony created: {}-of-{}",
        ceremony.manifest.threshold, ceremony.manifest.share_count
    );
    println!("Ceremony ID: {}", ceremony.manifest.ceremony_id);
    println!("Cold classical PK: {}", ceremony.manifest.cold_classical_pk);
    println!("Cold PQ PK: {}", ceremony.manifest.cold_pq_pk);
    println!("Distribute shares to separate custodians and physical locations.");
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_ceremony(keys: &indra_cli::ColdKeysFile, args: &[String]) -> indra_cli::ColdShareCeremony {
    indra_cli::generate_cold_share_ceremony(
        keys,
        parse_hex32_flag(args, "--validator-id"),
        parse_u8_flag(args, "--threshold"),
        parse_u8_flag(args, "--shares"),
        now_unix_seconds(),
        &mut rand::rngs::OsRng,
    )
    .unwrap_or_else(|e| cold_fail(e))
}

fn cmd_cold_ceremony(args: &[String]) {
    let mut keys = indra_cli::ColdKeysFile::generate().unwrap_or_else(|e| cold_fail(e));
    let ceremony = build_ceremony(&keys, args);
    write_ceremony(
        &ceremony,
        std::path::Path::new(&required(args, "--out-dir")),
        args.iter().any(|arg| arg == "--force"),
    );
    keys.zeroize_secret_material();
    println!("No complete cold secret was written to disk.");
}

fn cmd_cold_split(args: &[String]) {
    let mut keys = indra_cli::load_cold_keys(
        &required(args, "--cold-keys"),
        keygen_password_source_slice(args),
    )
    .unwrap_or_else(|e| cold_fail(e));
    let ceremony = build_ceremony(&keys, args);
    write_ceremony(
        &ceremony,
        std::path::Path::new(&required(args, "--out-dir")),
        args.iter().any(|arg| arg == "--force"),
    );
    keys.zeroize_secret_material();
    println!("The source keystore was not modified; retain or destroy it according to your ceremony policy.");
}

fn cmd_cold_verify(args: &[String]) {
    let shares = load_share_set(args);
    let mut keys = indra_cli::reconstruct_cold_shares(&shares).unwrap_or_else(|e| cold_fail(e));
    keys.reconstruct().unwrap_or_else(|e| cold_fail(e));
    keys.zeroize_secret_material();
    println!("Shares reconstruct the expected complete hybrid cold public key.");
    println!("No reconstructed key file was written.");
}

fn cmd_cold_recover(args: &[String]) {
    if !args
        .iter()
        .any(|arg| arg == "--acknowledge-destroy-after-use")
    {
        cold_fail("recover requires --acknowledge-destroy-after-use");
    }
    if args.iter().any(|arg| arg == "--plaintext-unsafe") {
        cold_fail("plaintext cold-key recovery is never supported");
    }
    let mut keys =
        indra_cli::reconstruct_cold_shares(&load_share_set(args)).unwrap_or_else(|e| cold_fail(e));
    let output = required(args, "--output");
    if std::path::Path::new(&output).exists() && !args.iter().any(|arg| arg == "--force") {
        cold_fail(format!(
            "{output} already exists; pass --force to overwrite"
        ));
    }
    let password = keygen_password_source_slice(args)
        .resolve(true)
        .unwrap_or_else(|e| cold_fail(e));
    let encrypted =
        indra_cli::encrypt_cold_keys(&keys, password.as_bytes()).unwrap_or_else(|e| cold_fail(e));
    indra_cli::write_keys_file_secure(&output, &encrypted).unwrap_or_else(|e| cold_fail(e));
    let mut verified = indra_keystore::decrypt_cold_keys(&encrypted, password.as_bytes())
        .unwrap_or_else(|e| cold_fail(e));
    if verified != keys {
        cold_fail("encrypted recovery output failed verification");
    }
    verified.zeroize_secret_material();
    keys.zeroize_secret_material();
    println!("Encrypted temporary cold keystore written to {output}.");
    println!("DESTROY THIS RECOVERED KEYSTORE IMMEDIATELY AFTER SIGNING OR RE-SHARING.");
}

fn cmd_cold_reshare(args: &[String]) {
    let shares = load_share_set(args);
    let mut keys = indra_cli::reconstruct_cold_shares(&shares).unwrap_or_else(|e| cold_fail(e));
    let mut ceremony_args = args.to_vec();
    if get(args, "--validator-id").is_none() {
        ceremony_args.push("--validator-id".into());
        ceremony_args.push(shares[0].manifest.validator_id.clone());
    }
    let ceremony = build_ceremony(&keys, &ceremony_args);
    write_ceremony(
        &ceremony,
        std::path::Path::new(&required(args, "--out-dir")),
        args.iter().any(|arg| arg == "--force"),
    );
    keys.zeroize_secret_material();
    println!("No intermediate complete cold keystore was written.");
}

fn get(args: &[String], flag: &str) -> Option<String> {
    get_ref(args, flag).map(ToString::to_string)
}

fn get_ref<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn keygen_password_source(args: &[String]) -> indra_cli::PasswordSource<'_> {
    keygen_password_source_slice(args)
}

fn keygen_password_source_slice(args: &[String]) -> indra_cli::PasswordSource<'_> {
    let path = get_ref(args, "--keys-password-file").or_else(|| get_ref(args, "--password-file"));
    if let Some(path) = path {
        indra_cli::PasswordSource::File {
            path: std::path::Path::new(path),
            reject_permissive: false,
        }
    } else if let Some(var) = get_ref(args, "--keys-password-env") {
        indra_cli::PasswordSource::Env(var)
    } else {
        indra_cli::PasswordSource::Prompt
    }
}

fn print_help() {
    println!(
        "Usage:\n  indra-keygen [--output keys.json] [--name name] [--chain-id id] [--recover|--passphrase] [--keys-password-file path|--plaintext-unsafe]\n  indra-keygen cold --output validator-cold-keys.json [--keys-password-file path | --plaintext-unsafe] [--force]\n  indra-keygen cold ceremony --validator-id <hex> --threshold <m> --shares <n> --out-dir <dir>\n  indra-keygen cold split --cold-keys <path> --validator-id <hex> --threshold <m> --shares <n> --out-dir <dir>\n  indra-keygen cold verify --share <path> [--share <path> ...]\n  indra-keygen cold recover --share <path> ... --output <encrypted.json> --acknowledge-destroy-after-use [--keys-password-file path]\n  indra-keygen cold reshare --share <path> ... --threshold <m> --shares <n> --out-dir <dir>\n  indra-keygen encrypt --keys keys.json (--out encrypted.json | --replace) [--password-file path]\n  indra-keygen decrypt --keys keys.json --out plaintext.json [--password-file path]\n  indra-keygen inspect --keys keys.json"
    );
}

fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty only observes the stdin fd.
        unsafe { libc::isatty(0) == 1 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn read_secret_from_stdin(prompt: &str) -> String {
    eprint!("{}", prompt);
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let echo_guard = EchoGuard::disable();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    drop(echo_guard);
    eprintln!();
    input.trim().to_string()
}

#[cfg(unix)]
struct EchoGuard {
    original: libc::termios,
    active: bool,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Self {
        let fd = 0;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `original` points to valid writable memory for libc to fill.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Self {
                // SAFETY: zeroed termios is never used when active=false.
                original: unsafe { std::mem::zeroed() },
                active: false,
            };
        }
        // SAFETY: tcgetattr succeeded, so `original` has been initialized.
        let original = unsafe { original.assume_init() };
        let mut no_echo = original;
        no_echo.c_lflag &= !libc::ECHO;
        // SAFETY: `no_echo` is a valid termios copied from the current terminal settings.
        let active = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } == 0;
        Self { original, active }
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: `original` came from a successful tcgetattr call for stdin.
            let _ = unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.original) };
        }
    }
}

#[cfg(not(unix))]
struct EchoGuard;

#[cfg(not(unix))]
impl EchoGuard {
    fn disable() -> Self {
        Self
    }
}
