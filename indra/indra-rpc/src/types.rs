//! JSON-RPC 2.0 request and response types.
//!
//! Request envelopes are parsed with `serde_json` and method parameters remain
//! represented as raw JSON value strings for the existing handler layer.

use serde_json::Value;

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
/// Strictly parses the JSON-RPC 2.0 envelope while preserving the existing
/// handler-facing representation of `params` as raw JSON value strings.
pub fn parse_request(json: &str) -> Result<RpcRequest, String> {
    let value: Value =
        serde_json::from_str(json.trim()).map_err(|error| format!("invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "JSON-RPC request must be an object".to_string())?;

    let jsonrpc = object
        .get("jsonrpc")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing or invalid 'jsonrpc' field".to_string())?;
    if jsonrpc != "2.0" {
        return Err("invalid 'jsonrpc' version: expected \"2.0\"".to_string());
    }

    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing or invalid 'method' field".to_string())?
        .to_string();

    let id = match object.get("id") {
        Some(Value::Number(number)) => number
            .as_i64()
            .map(JsonId::Number)
            .ok_or_else(|| "unsupported 'id' number".to_string())?,
        Some(Value::String(value)) => JsonId::Str(value.clone()),
        Some(Value::Null) | None => JsonId::Null,
        Some(_) => return Err("invalid 'id' field".to_string()),
    };

    let params = match object.get("params") {
        Some(Value::Array(values)) => values
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("invalid 'params' value: {error}"))?,
        Some(_) => return Err("'params' must be an array".to_string()),
        None => Vec::new(),
    };

    Ok(RpcRequest {
        jsonrpc: jsonrpc.to_string(),
        method,
        params,
        id,
    })
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
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "indra_getHeight");
        assert_eq!(req.params.len(), 0);
        assert!(matches!(req.id, JsonId::Number(1)));
    }

    #[test]
    fn parse_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","method":"indra_getBlock","params":["42"],"id":2}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "indra_getBlock");
        assert_eq!(req.params, vec![r#""42""#.to_string()]);
    }

    #[test]
    fn parse_request_preserves_raw_json_params_for_handlers() {
        let json = r#"{"jsonrpc":"2.0","method":"indra_method","params":["x",42,true,null,{"a":[1,2]}],"id":"abc"}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "indra_method");
        assert!(matches!(req.id, JsonId::Str(ref value) if value == "abc"));
        assert_eq!(
            req.params,
            vec![
                r#""x""#.to_string(),
                "42".to_string(),
                "true".to_string(),
                "null".to_string(),
                r#"{"a":[1,2]}"#.to_string(),
            ]
        );
    }

    #[test]
    fn parse_request_rejects_malformed_json_cleanly() {
        let err = parse_request(r#"{"jsonrpc":"2.0","method":"indra_getHeight","#)
            .err()
            .unwrap_or_default();
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn parse_request_rejects_missing_jsonrpc() {
        let err = parse_request(r#"{"method":"indra_getHeight","params":[],"id":1}"#)
            .err()
            .unwrap_or_default();
        assert!(err.contains("jsonrpc"), "{err}");
    }

    #[test]
    fn parse_request_rejects_incorrect_jsonrpc_version() {
        let err =
            parse_request(r#"{"jsonrpc":"1.0","method":"indra_getHeight","params":[],"id":1}"#)
                .err()
                .unwrap_or_default();
        assert!(err.contains("expected \"2.0\""), "{err}");
    }

    #[test]
    fn parse_request_rejects_top_level_array() {
        let err = parse_request(r#"[{"jsonrpc":"2.0","method":"indra_getHeight","id":1}]"#)
            .err()
            .unwrap_or_default();
        assert!(err.contains("must be an object"), "{err}");
    }

    #[test]
    fn parse_request_rejects_non_array_params() {
        let err = parse_request(
            r#"{"jsonrpc":"2.0","method":"indra_getHeight","params":{"x":1},"id":1}"#,
        )
        .err()
        .unwrap_or_default();
        assert!(err.contains("params"), "{err}");
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
