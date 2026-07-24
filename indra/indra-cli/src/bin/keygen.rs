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
    if args.get(1).map(String::as_str) == Some("add-payment-key") {
        cmd_add_payment_key(&args[2..]);
        return;
    }

    let output = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map_or("keys.json", String::as_str);
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
    let (name, public) = indra_cli::inspect_public_metadata(&json).unwrap_or_else(|e| {
        eprintln!("Failed to inspect keys: {}", e);
        std::process::exit(1);
    });
    println!("Validator Name: {}", name);
    println!("Validator ID:   {}", hex::encode(public.validator_id));
    println!(
        "Classical PK:   {}",
        hex::encode(public.hybrid_classical_pk)
    );
    println!("PQ PK bytes:    {}", public.hybrid_pq_pk.len());
    println!("BLS PK:         {}", hex::encode(public.bls_pk));
    println!("VRF PK:         {}", hex::encode(public.vrf_pk));
    if let Some(payment_pubkey) = &public.payment_pubkey {
        println!("Payment PK:     {}", hex::encode(payment_pubkey.encode()));
    } else {
        println!("Payment PK:     <absent>");
    }
}

fn cmd_add_payment_key(args: &[String]) {
    let keys_path = get(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let out = get(args, "--out");
    let replace = args.iter().any(|a| a == "--replace");
    let force = args.iter().any(|a| a == "--force");
    if replace && out.is_some() {
        eprintln!("Error: choose either --replace or --out, not both");
        std::process::exit(1);
    }
    let password = keygen_password_source_slice(args)
        .resolve(false)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read keystore password: {}", e);
            std::process::exit(1);
        });
    let out_path = out.as_deref().map(std::path::Path::new);
    let report = indra_cli::add_payment_key_to_file(
        std::path::Path::new(&keys_path),
        password.as_bytes(),
        out_path,
        replace,
        force,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to add payment key: {}", e);
        std::process::exit(1);
    });

    println!("INDRA payment key retrofit complete");
    println!("Input:       {}", keys_path);
    println!("Output:      {}", report.output_path.display());
    if let Some(backup) = &report.backup_path {
        println!("Backup:      {}", backup.display());
    }
    println!("Payment PK:  {}", report.payment_pubkey_hex);
    println!();
    println!("Identity material before/after check:");
    for (field, before, after, unchanged) in
        indra_cli::IdentityMaterialSnapshot::comparison_rows(&report.before, &report.after)
    {
        println!(
            "  {:<20} {}",
            field,
            if unchanged { "UNCHANGED" } else { "CHANGED" }
        );
        println!("    before: {}", before);
        println!("    after:  {}", after);
    }
    println!();
    println!("Only payment_keypair and public.payment_pubkey were added/updated.");
    if !replace {
        println!("Original file was not modified.");
    }
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
        "Usage:\n  indra-keygen [--output keys.json] [--name name] [--recover|--passphrase] [--keys-password-file path|--plaintext-unsafe]\n  indra-keygen encrypt --keys keys.json (--out encrypted.json | --replace) [--password-file path]\n  indra-keygen decrypt --keys keys.json --out plaintext.json [--password-file path]\n  indra-keygen inspect --keys keys.json\n  indra-keygen add-payment-key --keys keys.json [--keys-password-file path] [--out new-file.json | --replace] [--force]"
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
