//! Shared, bounded JSON-RPC client used by every networked CLI.

use std::{env, fmt, fs, path::PathBuf, sync::OnceLock, time::Duration};

use crate::error::{CliError, CliResult};

/// Maximum time spent establishing a connection.
pub const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time spent on one complete request, including reading its body.
pub const RPC_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum response body accepted from a node.
pub const RPC_RESPONSE_CAP_BYTES: u64 = 8 * 1024 * 1024;
const TOKEN_FILE_ENV: &str = "INDRA_RPC_TOKEN_FILE";
static TOKEN_FILE_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Errors deliberately independent of transport-specific details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcClientError {
    /// The URL is malformed or violates the transport policy.
    InvalidUrl(&'static str),
    /// The token-file path or its contents violate the token policy.
    TokenFile(&'static str),
    /// The response exceeded the configured cap.
    ResponseTooLarge,
    /// The server returned a redirect, which is never followed.
    Redirect,
    /// The bounded request timeout expired.
    Timeout,
    /// The transport failed without exposing transport details.
    Transport,
    /// The server returned a non-success status.
    HttpStatus(u16),
    /// The response body could not be read.
    ResponseBody,
}

impl fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) | Self::TokenFile(message) => f.write_str(message),
            Self::ResponseTooLarge => f.write_str("RPC response exceeds 8 MiB limit"),
            Self::Redirect => f.write_str("RPC redirects are not allowed"),
            Self::Timeout => f.write_str("RPC request timed out"),
            Self::Transport => f.write_str("RPC transport error"),
            Self::HttpStatus(status) => write!(f, "RPC server returned HTTP status {status}"),
            Self::ResponseBody => f.write_str("RPC response body could not be read"),
        }
    }
}

impl std::error::Error for RpcClientError {}

impl From<RpcClientError> for CliError {
    fn from(error: RpcClientError) -> Self {
        Self::Rpc(error.to_string())
    }
}

/// Configure the token-file path from one shared CLI argument helper.
pub fn configure_from_args(args: &[String]) -> CliResult<()> {
    if let Some(path) = flag_value(args, "--rpc-token-file") {
        if path.is_empty() || path.starts_with('-') {
            return Err(RpcClientError::TokenFile("--rpc-token-file requires a path").into());
        }
        // The environment variable stores only a path, never the token.
        // This is process-local CLI configuration and is read by post_json.
        TOKEN_FILE_OVERRIDE.set(PathBuf::from(path)).map_err(|_| {
            RpcClientError::TokenFile("RPC token file was configured more than once")
        })?;
    }
    Ok(())
}

/// Return a common help fragment for networked binaries.
pub fn rpc_token_help() -> &'static str {
    "  --rpc-token-file <path>  Private RPC token file (or INDRA_RPC_TOKEN_FILE)\n"
}

/// POST a JSON-RPC request through the shared client.
pub fn post_json(url: &str, body: &str) -> CliResult<String> {
    post_json_with_tls(url, body, token_path(), None)
}

#[cfg(test)]
fn post_json_with_path(url: &str, body: &str, token_path: Option<PathBuf>) -> CliResult<String> {
    post_json_with_tls(url, body, token_path, None)
}

fn post_json_with_tls(
    url: &str,
    body: &str,
    token_path: Option<PathBuf>,
    #[cfg(test)] test_root: Option<Vec<u8>>,
    #[cfg(not(test))] _test_root: Option<Vec<u8>>,
) -> CliResult<String> {
    post_json_with_limits(
        url,
        body,
        token_path,
        RPC_CONNECT_TIMEOUT,
        RPC_TOTAL_TIMEOUT,
        {
            #[cfg(test)]
            {
                test_root
            }
            #[cfg(not(test))]
            {
                _test_root
            }
        },
    )
}

fn post_json_with_limits(
    url: &str,
    body: &str,
    token_path: Option<PathBuf>,
    connect_timeout: Duration,
    total_timeout: Duration,
    #[cfg(test)] test_root: Option<Vec<u8>>,
    #[cfg(not(test))] _test_root: Option<Vec<u8>>,
) -> CliResult<String> {
    validate_url(url)?;
    let token = load_token_file(token_path)?;
    #[cfg(test)]
    let mut config = ureq::Agent::config_builder()
        .timeout_connect(Some(connect_timeout))
        .timeout_global(Some(total_timeout))
        .max_redirects(0)
        .max_redirects_will_error(false);
    #[cfg(not(test))]
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(connect_timeout))
        .timeout_global(Some(total_timeout))
        .max_redirects(0)
        .max_redirects_will_error(false);
    #[cfg(test)]
    if let Some(root) = test_root {
        let certificate =
            ureq::tls::Certificate::from_pem(&root).map_err(|_| RpcClientError::Transport)?;
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::new_with_certs(&[certificate]))
            .build();
        config = config.tls_config(tls);
    }
    let agent = config.build().new_agent();
    let mut request = agent.post(url).content_type("application/json");
    if let Some(token) = token.as_deref() {
        request = request.header("X-Rpc-Token", token);
    }
    let mut response = request.send(body).map_err(map_transport_error)?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(RpcClientError::Redirect.into());
    }
    if !(200..300).contains(&status) {
        return Err(RpcClientError::HttpStatus(status).into());
    }
    if response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > RPC_RESPONSE_CAP_BYTES)
    {
        return Err(RpcClientError::ResponseTooLarge.into());
    }
    response
        .body_mut()
        .with_config()
        .limit(RPC_RESPONSE_CAP_BYTES)
        .read_to_string()
        .map_err(|error| {
            if error.to_string().contains("body exceeds limit") {
                RpcClientError::ResponseTooLarge.into()
            } else {
                RpcClientError::ResponseBody.into()
            }
        })
}

fn validate_url(url: &str) -> Result<(), RpcClientError> {
    let (scheme, rest) = url.split_once("://").ok_or(RpcClientError::InvalidUrl(
        "RPC URL must include http:// or https://",
    ))?;
    if scheme != "http" && scheme != "https" {
        return Err(RpcClientError::InvalidUrl("RPC URL scheme is unsupported"));
    }
    if scheme == "http" {
        let authority = rest.split('/').next().unwrap_or_default();
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split_once(']').map_or("", |(host, _)| host)
        } else {
            authority
                .split_once(':')
                .map_or(authority, |(host, _)| host)
        };
        if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
            return Err(RpcClientError::InvalidUrl(
                "plain http is only allowed for loopback nodes; use https",
            ));
        }
    }
    Ok(())
}

fn token_path() -> Option<PathBuf> {
    TOKEN_FILE_OVERRIDE
        .get()
        .cloned()
        .or_else(|| env::var_os(TOKEN_FILE_ENV).map(PathBuf::from))
}

fn load_token_file(path: Option<PathBuf>) -> Result<Option<String>, RpcClientError> {
    let Some(path) = path else { return Ok(None) };
    let metadata =
        fs::metadata(&path).map_err(|_| RpcClientError::TokenFile("cannot read RPC token file"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(RpcClientError::TokenFile(
                "RPC token file must not be readable by group or others",
            ));
        }
    }
    let mut token = fs::read_to_string(&path)
        .map_err(|_| RpcClientError::TokenFile("cannot read RPC token file"))?;
    if token.ends_with('\n') {
        token.pop();
        if token.ends_with('\r') {
            token.pop();
        }
    }
    if token.is_empty() {
        return Err(RpcClientError::TokenFile("RPC token file is empty"));
    }
    Ok(Some(token))
}

fn map_transport_error(error: ureq::Error) -> CliError {
    match error {
        ureq::Error::Timeout(_) => RpcClientError::Timeout.into(),
        _ => RpcClientError::Transport.into(),
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find_map(|pair| match pair {
        [candidate, value] if candidate == flag => Some(value.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::Command,
        thread,
    };

    fn server(response: &'static str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let size = stream.read(&mut request).unwrap();
            assert!(size > 0);
            stream.write_all(response.as_bytes()).unwrap();
        });
        address
    }

    fn header_server(response: &'static str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let size = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request[..size]).into_owned()
        });
        (address, handle)
    }

    fn self_signed_tls_server() -> (String, Vec<u8>, std::path::PathBuf, std::process::Child) {
        let dir = std::env::temp_dir().join(format!("indra-rpc-tls-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let generated = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-days",
                "1",
            ])
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let child = Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &port.to_string(),
                "-cert",
                cert_path.to_str().unwrap(),
                "-key",
                key_path.to_str().unwrap(),
                "-www",
                "-quiet",
            ])
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        (
            format!("https://localhost:{port}"),
            fs::read(cert_path).unwrap(),
            dir,
            child,
        )
    }

    #[test]
    fn loopback_http_is_allowed_and_redirect_is_rejected() {
        let url = server("HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            post_json(&url, "{}").unwrap_err().to_string(),
            "RPC error: RPC redirects are not allowed"
        );
    }

    #[test]
    fn non_loopback_http_is_rejected_exactly() {
        assert_eq!(
            post_json("http://example.com", "{}")
                .unwrap_err()
                .to_string(),
            "RPC error: plain http is only allowed for loopback nodes; use https"
        );
    }

    #[test]
    fn response_cap_is_rejected() {
        let url = server("HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n");
        assert_eq!(
            post_json(&url, "{}").unwrap_err().to_string(),
            "RPC error: RPC response exceeds 8 MiB limit"
        );
    }

    #[test]
    fn connect_timeout_is_bounded_by_private_test_configuration() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let started = std::time::Instant::now();
        let error = post_json_with_limits(
            &address,
            "{}",
            None,
            Duration::from_millis(25),
            Duration::from_millis(250),
            None,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "RPC error: RPC transport error");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn read_timeout_is_bounded_by_private_test_configuration() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_secs(1));
        });
        let error = post_json_with_limits(
            &address,
            "{}",
            None,
            Duration::from_millis(250),
            Duration::from_millis(50),
            None,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "RPC error: RPC request timed out");
        handle.join().unwrap();
    }

    #[test]
    fn token_file_policy_is_exact_and_token_is_not_in_error() {
        let path = std::env::temp_dir().join(format!("indra-rpc-token-{}", std::process::id()));
        fs::write(&path, b"secret\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = load_token_file(Some(path.clone())).unwrap_err().to_string();
        assert_eq!(
            error,
            "RPC token file must not be readable by group or others"
        );
        assert!(!error.contains("secret"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn token_header_is_sent_and_empty_file_is_rejected() {
        let path =
            std::env::temp_dir().join(format!("indra-rpc-token-header-{}", std::process::id()));
        fs::write(&path, b"secret-token\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (url, handle) = header_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        assert_eq!(
            post_json_with_path(&url, "{}", Some(path.clone())).unwrap(),
            "ok"
        );
        let request = handle.join().unwrap();
        assert!(request
            .to_ascii_lowercase()
            .contains("x-rpc-token: secret-token"));
        fs::write(&path, b"").unwrap();
        assert_eq!(
            post_json_with_path(&url, "{}", Some(path.clone()))
                .unwrap_err()
                .to_string(),
            "RPC error: RPC token file is empty"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn index5_rpc_client_flag_as_last_argument_is_not_indexed() {
        let args = vec![
            "--node".to_string(),
            "http://127.0.0.1:8545".to_string(),
            "--rpc-token-file".to_string(),
        ];
        assert_eq!(flag_value(&args, "--rpc-token-file"), None);
    }

    #[test]
    fn index5_rpc_client_repeated_flags_use_the_first_complete_pair() {
        let args = vec![
            "--rpc-token-file".to_string(),
            "first".to_string(),
            "--rpc-token-file".to_string(),
            "second".to_string(),
        ];
        assert_eq!(
            flag_value(&args, "--rpc-token-file"),
            Some("first".to_string())
        );
    }

    #[test]
    fn index5_rpc_client_empty_flag_value_is_preserved() {
        let args = vec!["--rpc-token-file".to_string(), String::new()];
        assert_eq!(flag_value(&args, "--rpc-token-file"), Some(String::new()));
    }

    #[test]
    fn index5_rpc_client_missing_flag_value_is_not_indexed() {
        let args = vec!["--rpc-token-file".to_string()];
        assert_eq!(flag_value(&args, "--rpc-token-file"), None);
    }

    #[test]
    fn self_signed_https_is_rejected_without_test_ca_and_accepted_with_it() {
        let (url, _cert, dir, mut child) = self_signed_tls_server();
        assert_eq!(
            post_json(&url, "{}").unwrap_err().to_string(),
            "RPC error: RPC transport error"
        );
        child.kill().unwrap();
        child.wait().unwrap();
        fs::remove_dir_all(&dir).unwrap();

        let (url, cert, dir, mut child) = self_signed_tls_server();
        let certificate = ureq::tls::Certificate::from_pem(&cert).unwrap();
        let agent = ureq::Agent::config_builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&[certificate]))
                    .build(),
            )
            .build()
            .new_agent();
        assert!(agent.get(&url).call().is_ok());
        child.kill().unwrap();
        child.wait().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
