fn main() {
    let args: Vec<String> = std::env::args().collect();
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

    let json = keys.to_json();
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
    println!("  Keys written to:  {}", output);
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
