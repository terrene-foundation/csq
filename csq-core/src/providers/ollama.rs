//! Ollama integration — query local Ollama server for available models.

use tracing::debug;

/// Returns the list of locally-installed Ollama models.
///
/// Runs `ollama list` and parses the output. Returns empty list if
/// Ollama is not installed or the command fails.
pub fn get_ollama_models() -> Vec<String> {
    let output = match std::process::Command::new("ollama").arg("list").output() {
        Ok(o) => o,
        Err(e) => {
            debug!(error = %e, "ollama not available");
            return vec![];
        }
    };

    if !output.status.success() {
        debug!("ollama list returned non-zero exit");
        return vec![];
    }

    parse_ollama_list(&String::from_utf8_lossy(&output.stdout))
}

/// Parses the output of `ollama list`.
///
/// Expected format (tab-separated):
/// ```text
/// NAME                    ID              SIZE    MODIFIED
/// llama3.3:latest         abc123          4.7 GB  2 hours ago
/// qwen2.5-coder:32b       def456          19 GB   1 day ago
/// ```
pub fn parse_ollama_list(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1) // Skip header
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            // First whitespace-separated token is the model name
            trimmed.split_whitespace().next().map(|s| s.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_output() {
        let output = "NAME                    ID              SIZE    MODIFIED
llama3.3:latest         abc123          4.7 GB  2 hours ago
qwen2.5-coder:32b       def456          19 GB   1 day ago
gpt-oss:20b             789abc          13 GB   3 days ago";

        let models = parse_ollama_list(output);
        assert_eq!(models.len(), 3);
        assert_eq!(models[0], "llama3.3:latest");
        assert_eq!(models[1], "qwen2.5-coder:32b");
        assert_eq!(models[2], "gpt-oss:20b");
    }

    #[test]
    fn parse_empty_output() {
        assert!(parse_ollama_list("").is_empty());
    }

    #[test]
    fn parse_header_only() {
        let output = "NAME                    ID              SIZE    MODIFIED";
        assert!(parse_ollama_list(output).is_empty());
    }

    #[test]
    fn parse_with_blank_lines() {
        let output = "NAME ID SIZE
llama3.3 abc 4GB

gpt-oss:20b def 13GB
";
        let models = parse_ollama_list(output);
        assert_eq!(models, vec!["llama3.3", "gpt-oss:20b"]);
    }
}
