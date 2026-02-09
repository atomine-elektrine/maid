fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn extract_command(raw: &str) -> String {
    for marker in ["\"command\":\"", "\"command\": \""] {
        if let Some(start) = raw.find(marker) {
            let start = start + marker.len();
            if let Some(rest) = raw.get(start..) {
                if let Some(end) = rest.find('"') {
                    return rest[..end].to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

fn main() {
    let raw = std::env::var("MAID_PLUGIN_REQUEST").unwrap_or_default();
    if raw.trim().is_empty() {
        println!(
            "{{\"ok\":false,\"message\":\"MAID_PLUGIN_REQUEST is missing\",\"output\":null,\"data\":null}}"
        );
        return;
    }

    let command = extract_command(&raw);
    let escaped_raw = json_escape(&raw);
    let escaped_command = json_escape(&command);
    println!(
        "{{\"ok\":true,\"message\":\"echo plugin executed\",\"output\":\"command={}\",\"data\":{{\"raw_request\":\"{}\"}}}}",
        escaped_command, escaped_raw
    );
}
