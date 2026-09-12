use reqwest::Client;
use serde_json::Value;

/// Extracts the core error message or exception signature from a multi-line log.
/// Filters out stack frames, memory addresses, and truncation boilerplate.
pub fn extract_error_query(log: &str) -> Option<String> {
    // 1. Prioritize root cause lines (Java Caused by)
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Caused by:") {
            let msg = trimmed.trim_start_matches("Caused by:").trim();
            return Some(clean_query(msg));
        }
    }

    // 2. Check for explicit panics or sanitizer violations
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("panic:") {
            let msg = trimmed.trim_start_matches("panic:").trim();
            return Some(clean_query(msg));
        }
        if trimmed.starts_with("thread ") && trimmed.contains("panicked at") {
            if let Some((_, msg)) = trimmed.split_once("panicked at") {
                return Some(clean_query(msg.trim().trim_matches('\'').trim_matches('"')));
            }
        }
        if trimmed.contains("AddressSanitizer:") {
            if let Some((_, msg)) = trimmed.split_once("AddressSanitizer:") {
                let token = msg.split_whitespace().next().unwrap_or("heap-buffer-overflow");
                return Some(clean_query(token));
            }
        }
    }

    // 3. Scan lines for standard exception / error headers
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Exception in thread") {
            if let Some((_, msg)) = trimmed.split_once(':') {
                return Some(clean_query(msg.trim()));
            }
        }
        if trimmed.contains("Error: ") || trimmed.contains("Exception: ") {
            if !trimmed.starts_with("at ") && !trimmed.starts_with("File \"") && !trimmed.starts_with('#') {
                return Some(clean_query(trimmed));
            }
        }
    }

    // 4. Fallback: Find the most descriptive non-stack, non-noise line from bottom up
    for line in log.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Discard stack frames and runtime metadata
        if trimmed.starts_with("at ")
            || trimmed.starts_with("File \"")
            || trimmed.starts_with('#')
            || trimmed.starts_with("goroutine ")
            || trimmed.starts_with("... ")
            || trimmed.starts_with("+0x")
            || trimmed.starts_with("runtime.")
            || trimmed.starts_with("exit status")
        {
            continue;
        }
        return Some(clean_query(trimmed));
    }

    None
}

fn clean_query(raw: &str) -> String {
    // Strip raw memory pointers (0x...) and file path fragments, preserving language packages (e.g. net/http)
    let words: Vec<&str> = raw.split_whitespace().collect();
    let cleaned: Vec<&str> = words
        .into_iter()
        .filter(|w| {
            let lower = w.to_lowercase();
            !w.starts_with("0x")
                && !w.starts_with('/')
                && !lower.starts_with("c:\\")
                && !lower.starts_with("d:\\")
                && !lower.contains("/home/")
                && !lower.contains("/usr/")
                && !lower.contains("/var/")
                && !lower.contains("/etc/")
                && !lower.contains("/app/")
                && !lower.contains("/target/")
        })
        .collect();
    let res = if cleaned.is_empty() {
        raw.to_string()
    } else {
        cleaned.join(" ")
    };
    res.chars().take(100).collect()
}

pub async fn search_stackoverflow(log: &str) -> Option<String> {
    let query = extract_error_query(log)?;
    if query.trim().is_empty() {
        return None;
    }

    let url = format!(
        "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&q={}&site=stackoverflow",
        urlencoding::encode(&query)
    );

    let client = Client::builder()
        .user_agent("tokenectomy-cli")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    let response = client.get(&url).send().await.ok()?;
    let json: Value = response.json().await.ok()?;

    let mut results = String::from("Based on automated Stack Overflow search:\n");
    let mut found = false;

    if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
        for item in items.iter().take(3) {
            if let (Some(title), Some(link), Some(is_answered)) = (
                item.get("title"),
                item.get("link"),
                item.get("is_answered"),
            ) {
                let title = title.as_str().unwrap_or("");
                let link = link.as_str().unwrap_or("");
                let answered = if is_answered.as_bool().unwrap_or(false) {
                    "✅ Answered"
                } else {
                    "⏳ Unanswered"
                };

                results.push_str(&format!("- [{}] {}\n  {}\n", answered, title, link));
                found = true;
            }
        }
    }

    if found {
        Some(results)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_error_query_java_caused_by() {
        let log = r#"
org.springframework.web.util.NestedServletException: Request processing failed
	at org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1014)
Caused by: java.lang.NullPointerException: user repository returned null
	at com.example.service.OrderService.processOrder(OrderService.java:64)
	... 42 common frames omitted
"#;
        let query = extract_error_query(log).expect("should extract query");
        assert!(query.contains("NullPointerException"));
        assert!(!query.contains("common frames omitted"));
        assert!(!query.contains("OrderService.java"));
    }

    #[test]
    fn test_extract_error_query_go_panic() {
        let log = r#"
panic: runtime error: index out of range [3] with length 2
goroutine 1 [running]:
main.main()
	/app/main.go:15 +0x2b
"#;
        let query = extract_error_query(log).expect("should extract query");
        assert!(query.contains("runtime error: index out of range"));
        assert!(!query.contains("main.go"));
    }

    #[test]
    fn test_extract_error_query_python_error() {
        let log = r#"
Traceback (most recent call last):
  File "app.py", line 12, in <module>
    run()
TypeError: unsupported operand type(s) for +: 'int' and 'str'
"#;
        let query = extract_error_query(log).expect("should extract query");
        assert!(query.contains("TypeError"));
    }
}
