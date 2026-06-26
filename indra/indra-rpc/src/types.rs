//! JSON-RPC 2.0 request and response types.
//!
//! All serialisation is manual (no serde) to keep dependencies minimal.
//! Values are represented as JSON strings and parsed on demand.

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone)]
pub struct RpcRequest {
    /// Must be "2.0".
    pub jsonrpc: String,
    /// The method name.
    pub method: String,
    /// Parameters as a raw JSON array string.
    pub params: Vec<String>,
    /// Request ID (string or number).
    pub id: JsonId,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone)]
pub struct RpcResponse {
    /// Always "2.0".
    pub jsonrpc: String,
    /// The result or error.
    pub body: ResponseBody,
    /// Matches the request ID.
    pub id: JsonId,
}

/// The body of an RPC response.
#[derive(Debug, Clone)]
pub enum ResponseBody {
    /// Successful result as a JSON value string.
    Result(String),
    /// Error body.
    Error(RpcErrorBody),
}

/// JSON-RPC error body.
#[derive(Debug, Clone)]
pub struct RpcErrorBody {
    /// Error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
}

/// A JSON-RPC ID — either a number or a string.
#[derive(Debug, Clone)]
pub enum JsonId {
    /// Numeric ID.
    Number(i64),
    /// String ID.
    Str(String),
    /// Null ID (notification).
    Null,
}

impl JsonId {
    /// Serialise the id as a JSON value.
    pub fn to_json(&self) -> String {
        match self {
            JsonId::Number(n) => n.to_string(),
            JsonId::Str(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            JsonId::Null => "null".to_string(),
        }
    }
}

impl RpcResponse {
    /// Serialise to JSON string.
    pub fn to_json(&self) -> String {
        let id_str = self.id.to_json();

        match &self.body {
            ResponseBody::Result(result) => {
                format!(r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#, result, id_str)
            }
            ResponseBody::Error(err) => {
                format!(
                    r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":{}}}"#,
                    err.code,
                    err.message.replace('"', "\\\""),
                    id_str
                )
            }
        }
    }

    /// Build a success response.
    pub fn ok(id: JsonId, result: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            body: ResponseBody::Result(result),
            id,
        }
    }

    /// Build an error response.
    pub fn err(id: JsonId, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            body: ResponseBody::Error(RpcErrorBody { code, message }),
            id,
        }
    }
}

/// Parse a JSON-RPC request from a raw JSON string.
///
/// Minimal parser — handles the standard JSON-RPC 2.0 envelope.
pub fn parse_request(json: &str) -> Result<RpcRequest, String> {
    let json = json.trim();

    // Extract method
    let method =
        extract_string_field(json, "method").ok_or_else(|| "missing 'method' field".to_string())?;

    // Extract jsonrpc
    let jsonrpc = extract_string_field(json, "jsonrpc").unwrap_or_else(|| "2.0".to_string());

    // Extract id
    let id = extract_id(json);

    // Extract params array (simplified: extract as individual string tokens)
    let params = extract_params(json);

    Ok(RpcRequest {
        jsonrpc,
        method,
        params,
        id,
    })
}

/// Extract a string field value from a JSON object.
fn extract_string_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\"", field);
    let pos = json.find(&key)?;
    let after_key = &json[pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if let Some(content) = after_colon.strip_prefix('"') {
        // String value
        let end = content.find('"')?;
        Some(content[..end].to_string())
    } else {
        None
    }
}

/// Extract the id field (string or number).
fn extract_id(json: &str) -> JsonId {
    let key = "\"id\"";
    let pos = match json.find(key) {
        Some(p) => p,
        None => return JsonId::Null,
    };
    let after_key = &json[pos + key.len()..];
    let colon_pos = match after_key.find(':') {
        Some(p) => p,
        None => return JsonId::Null,
    };
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if let Some(content) = after_colon.strip_prefix('"') {
        if let Some(end) = content.find('"') {
            return JsonId::Str(content[..end].to_string());
        }
    } else if after_colon.starts_with("null") {
        return JsonId::Null;
    } else {
        // Try to parse as number
        let num_str: String = after_colon
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        if let Ok(n) = num_str.parse::<i64>() {
            return JsonId::Number(n);
        }
    }
    JsonId::Null
}

/// Extract params array as a list of raw JSON value strings.
fn extract_params(json: &str) -> Vec<String> {
    let key = "\"params\"";
    let pos = match json.find(key) {
        Some(p) => p,
        None => return vec![],
    };
    let after_key = &json[pos + key.len()..];
    let colon_pos = match after_key.find(':') {
        Some(p) => p,
        None => return vec![],
    };
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if !after_colon.starts_with('[') {
        return vec![];
    }

    // Find the matching closing bracket
    let mut depth = 0i32;
    let mut end = 0;
    for (i, c) in after_colon.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }

    let array_content = &after_colon[1..end]; // strip outer [ ]
    if array_content.trim().is_empty() {
        return vec![];
    }

    // Split by top-level commas
    let mut params = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut prev_char = ' ';

    for c in array_content.chars() {
        match c {
            '"' if prev_char != '\\' => {
                in_string = !in_string;
                current.push(c);
            }
            '[' | '{' if !in_string => {
                depth += 1;
                current.push(c);
            }
            ']' | '}' if !in_string => {
                depth -= 1;
                current.push(c);
            }
            ',' if !in_string && depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    params.push(trimmed);
                }
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
        prev_char = c;
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        params.push(trimmed);
    }

    params
}

/// Strip surrounding quotes from a JSON string value.
pub fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_request() {
        let json = r#"{"jsonrpc":"2.0","method":"indra_getHeight","params":[],"id":1}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "indra_getHeight");
        assert_eq!(req.params.len(), 0);
        assert!(matches!(req.id, JsonId::Number(1)));
    }

    #[test]
    fn parse_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","method":"indra_getBlock","params":["42"],"id":2}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "indra_getBlock");
        assert_eq!(req.params.len(), 1);
    }

    #[test]
    fn response_ok_serialises() {
        let resp = RpcResponse::ok(JsonId::Number(1), r#"{"height":42}"#.to_string());
        let json = resp.to_json();
        assert!(json.contains("\"result\""));
        assert!(json.contains("42"));
    }

    #[test]
    fn response_error_serialises() {
        let resp = RpcResponse::err(JsonId::Number(1), -32601, "Method not found".to_string());
        let json = resp.to_json();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn string_id_serialises() {
        let resp = RpcResponse::ok(JsonId::Str("abc".to_string()), "null".to_string());
        let json = resp.to_json();
        assert!(json.contains("\"abc\""));
    }
}
