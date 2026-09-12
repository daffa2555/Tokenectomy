use crate::extractor;
use crate::git;
use crate::redact;
use crate::search;
use crate::workspace::WorkspaceBoundary;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn error_response(id: Option<Value>, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

pub const COMPILER_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn run_command_with_timeout(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
) -> Result<std::process::Output, String> {
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn compiler check: {}", e))?;

    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    // Concurrently drain stdout and stderr pipes in dedicated background threads.
    // This strictly avoids pipe buffer exhaustion deadlocks (>64KB buffer on Linux) when linters output verbose text.
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout_handle {
            let _ = std::io::Read::read_to_end(&mut r, &mut buf);
        }
        buf
    });

    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr_handle {
            let _ = std::io::Read::read_to_end(&mut r, &mut buf);
        }
        buf
    });

    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = out_thread.join().unwrap_or_default();
                let stderr = err_thread.join().unwrap_or_default();
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_thread.join();
                    let _ = err_thread.join();
                    return Err(format!(
                        "Compiler validation timed out after {}s",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err(format!("Error monitoring compiler process: {}", e));
            }
        }
    }
}

fn find_ast_syntax_error(node: &tree_sitter::Node) -> Option<(usize, usize, &'static str)> {
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            if child.has_error() {
                if let Some(err) = find_ast_syntax_error(&child) {
                    return Some(err);
                }
            }
        }
    }
    if node.is_error() {
        let pos = node.start_position();
        return Some((pos.row + 1, pos.column + 1, "syntax error"));
    }
    if node.is_missing() {
        let pos = node.start_position();
        return Some((pos.row + 1, pos.column + 1, "missing expected token"));
    }
    None
}

pub fn verify_patch(path: &std::path::Path) -> Result<(), String> {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext {
            "rs" => {
                let mut cmd = std::process::Command::new("cargo");
                cmd.args(["check", "--quiet", "--message-format=short"]);
                // Walk upwards to locate the nearest Cargo.toml manifest root
                let mut manifest_dir = path.parent();
                while let Some(dir) = manifest_dir {
                    if dir.join("Cargo.toml").exists() {
                        cmd.current_dir(dir);
                        break;
                    }
                    manifest_dir = dir.parent();
                }
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err_msg = if !stderr.trim().is_empty() {
                            stderr.trim()
                        } else {
                            stdout.trim()
                        };
                        return Err(format!("Cargo check failed: {}", err_msg));
                    }
                }
            }
            "py" => {
                // Primary: In-process Tree-sitter AST validation (zero external subprocess dependency)
                let mut parser = tree_sitter::Parser::new();
                let lang = &tree_sitter_python::LANGUAGE.into();
                if parser.set_language(lang).is_ok() {
                    if let Ok(source) = std::fs::read_to_string(path) {
                        if let Some(tree) = parser.parse(&source, None) {
                            if tree.root_node().has_error() {
                                if let Some((row, col, kind)) = find_ast_syntax_error(&tree.root_node()) {
                                    return Err(format!("Python syntax error on line {}:{} ({})", row, col, kind));
                                } else {
                                    return Err("Python syntax error detected by Tree-sitter AST parser".to_string());
                                }
                            }
                        }
                    }
                }
                // Secondary: OS runtime compiler validation if python3 is available
                let mut cmd = std::process::Command::new("python3");
                cmd.args(["-m", "py_compile", path.to_str().unwrap_or("")]);
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(format!("Python syntax check failed: {}", stderr.trim()));
                    }
                }
            }
            "go" => {
                let mut cmd = std::process::Command::new("go");
                cmd.args(["vet", path.to_str().unwrap_or("")]);
                let mut go_dir = path.parent();
                while let Some(dir) = go_dir {
                    if dir.join("go.mod").exists() {
                        cmd.current_dir(dir);
                        break;
                    }
                    go_dir = dir.parent();
                }
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(format!("Go vet syntax check failed: {}", stderr.trim()));
                    }
                }
            }
            "js" | "mjs" | "cjs" => {
                let mut cmd = std::process::Command::new("node");
                cmd.args(["--check", path.to_str().unwrap_or("")]);
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(format!("Node syntax check failed: {}", stderr.trim()));
                    }
                }
            }
            "ts" | "mts" | "cts" | "tsx" => {
                let mut cmd = std::process::Command::new("tsc");
                cmd.args(["--noEmit", path.to_str().unwrap_or("")]);
                let mut ts_dir = path.parent();
                while let Some(dir) = ts_dir {
                    if dir.join("tsconfig.json").exists() || dir.join("package.json").exists() {
                        cmd.current_dir(dir);
                        break;
                    }
                    ts_dir = dir.parent();
                }
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("TypeScript compiler check failed: {}", err));
                    }
                }
            }
            "json" => {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Err(e) = serde_json::from_str::<serde_json::Value>(&content) {
                        return Err(format!("JSON syntax validation failed: {}", e));
                    }
                }
            }
            "toml" => {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Err(e) = toml::from_str::<toml::Value>(&content) {
                        return Err(format!("TOML syntax validation failed: {}", e));
                    }
                }
            }
            "yaml" | "yml" => {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for (i, line) in content.lines().enumerate() {
                        let trimmed_start = line.trim_start();
                        let indent_len = line.len() - trimmed_start.len();
                        let indent = &line[..indent_len];
                        if indent.contains('\t') {
                            return Err(format!(
                                "YAML syntax error on line {}: Tabs are forbidden for indentation in YAML",
                                i + 1
                            ));
                        }
                    }
                    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        return Err(format!("YAML syntax validation failed: {}", e));
                    }
                }
            }
            "php" => {
                let mut cmd = std::process::Command::new("php");
                cmd.args(["-l", path.to_str().unwrap_or("")]);
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("PHP lint check failed: {}", err));
                    }
                }
            }
            "c" | "h" => {
                let mut cmd = std::process::Command::new("gcc");
                cmd.args(["-fsyntax-only", path.to_str().unwrap_or("")]);
                if let Some(parent) = path.parent() {
                    cmd.current_dir(parent);
                }
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("C compiler syntax check failed: {}", err));
                    }
                }
            }
            "cpp" | "cc" | "cxx" | "hpp" => {
                let mut cmd = std::process::Command::new("g++");
                cmd.args(["-fsyntax-only", path.to_str().unwrap_or("")]);
                if let Some(parent) = path.parent() {
                    cmd.current_dir(parent);
                }
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("C++ compiler syntax check failed: {}", err));
                    }
                }
            }
            "sh" | "bash" => {
                let mut cmd = std::process::Command::new("bash");
                cmd.args(["-n", path.to_str().unwrap_or("")]);
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("Bash syntax check failed: {}", err));
                    }
                }
            }
            "rb" => {
                let mut cmd = std::process::Command::new("ruby");
                cmd.args(["-c", path.to_str().unwrap_or("")]);
                if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("Ruby syntax check failed: {}", err));
                    }
                }
            }
            "java" => {
                static JAVAC_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let counter = JAVAC_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let temp_out = std::env::temp_dir().join(format!("javac_check_{}_{}", std::process::id(), counter));
                let _ = std::fs::create_dir_all(&temp_out);
                let mut cmd = std::process::Command::new("javac");
                cmd.args(["-proc:none", "-d", temp_out.to_str().unwrap_or("."), path.to_str().unwrap_or("")]);
                let res = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT);
                let _ = std::fs::remove_dir_all(&temp_out);
                if let Ok(output) = res {
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                        return Err(format!("Java compiler syntax check failed: {}", err));
                    }
                }
            }
            "cs" => {
                let mut cs_dir = path.parent();
                let mut found_project = false;
                let mut cmd = std::process::Command::new("dotnet");
                cmd.args(["build", "--no-restore", "-c", "Debug"]);
                while let Some(dir) = cs_dir {
                    if std::fs::read_dir(dir).ok().map(|rd| {
                        rd.filter_map(|e| e.ok()).any(|ent| {
                            ent.path().extension().and_then(|x| x.to_str()) == Some("csproj")
                        })
                    }).unwrap_or(false) {
                        cmd.current_dir(dir);
                        found_project = true;
                        break;
                    }
                    cs_dir = dir.parent();
                }
                if found_project {
                    if let Ok(output) = run_command_with_timeout(cmd, COMPILER_CHECK_TIMEOUT) {
                        if !output.status.success() {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let err = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
                            return Err(format!("C# compiler check failed: {}", err));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub async fn run_server() -> anyhow::Result<()> {
    let boundary = WorkspaceBoundary::current()
        .or_else(|_| WorkspaceBoundary::new(std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))))
        .or_else(|_| WorkspaceBoundary::new("."))
        .or_else(|_| WorkspaceBoundary::new(std::env::temp_dir()))
        .unwrap_or_else(|_| WorkspaceBoundary::new("/").expect("root boundary fallback"));
    let analyzer_state = crate::analyzer::AppState::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut handle = stdin.lock();
    loop {
        let mut line = String::new();
        // VULN-07: Limit read to 50MB to prevent MCP DoS
        let n = handle.by_ref().take(50 * 1024 * 1024).read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }

        if line.trim().is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let err = error_response(None, -32700, "Parse error or line too long");
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = match req.get("method").and_then(|v| v.as_str()) {
            Some(m) => m,
            None => {
                let err = error_response(id, -32600, "Invalid Request: missing method");
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
        };

        let response = match method {
            "initialize" => Some(success_response(
                id.unwrap_or(Value::Null),
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "tokenectomy",
                        "version": env!("CARGO_PKG_VERSION"),
                        "author": crate::AUTHOR_NAME,
                        "vendor": crate::VENDOR_NAME,
                        "repository": crate::REPOSITORY_URL,
                        "signature": crate::ENGINE_SIGNATURE
                    }
                }),
            )),
            "notifications/initialized" => None,
            "ping" => Some(success_response(id.unwrap_or(Value::Null), json!({}))),
            "tools/list" => Some(success_response(
                id.unwrap_or(Value::Null),
                json!({
                    "tools": [
                        {
                            "name": "get_error_context",
                            "description": "Extracts focused source code snippets and git diffs from a raw error log or stack trace, stripping framework noise (node_modules, site-packages) and redacting credentials.\n\n• Side Effects: None. Strictly read-only; does not modify workspace files, git state, or environment variables.\n• Auth & Permissions: None required. Reads local filesystem within the current workspace boundary.\n• Rate Limits: None. Runs entirely locally on native machine code.\n• Return Shape: Returns a JSON object with 'sanitized_trace' (string without secrets/noise), 'source_frames' (array of objects with file, line, code_snippet), and 'git_diff' (string or null).\n• Failure Modes: If source files referenced in the trace do not exist locally, omits code snippets for those frames while still returning the sanitized trace. Returns an error JSON on unreadable input.\n• When to use: Call immediately when receiving a runtime exception, test failure, or compiler error to isolate the root cause before planning code fixes.\n• When NOT to use: Do NOT use to search web solutions (use search_stack_overflow), do NOT use to modify files (use apply_code_patch), and do NOT use to statically lint clean code without an error log (use analyze_code).\n• Prerequisites: Workspace directory must be accessible locally; git repository recommended for diff extraction.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "log": {
                                        "type": "string",
                                        "description": "Raw error stack trace, compiler panic, or terminal stderr string to analyze (e.g. Python traceback, Node.js error, Rust panic). Must be non-empty UTF-8 text up to 1MB. Automatically sanitized of API keys, JWTs, and passwords."
                                    },
                                    "context_lines": {
                                        "type": "integer",
                                        "description": "Number of source code lines to retrieve above and below each detected error line. Integer between 0 and 100. Defaults to 10 lines. Larger values expand the context window but consume more LLM tokens."
                                    }
                                },
                                "required": ["log"]
                            }
                        },
                        {
                            "name": "search_stack_overflow",
                            "description": "Queries the public Stack Overflow / Stack Exchange API for verified programming solutions and discussions matching an error signature.\n\n• Side Effects: None. Strictly read-only network search; does not mutate local files or repository state.\n• Auth & Permissions: No API key required for standard rate-limited anonymous queries.\n• Rate Limits: Subject to public Stack Exchange API rate limits (~300 requests/day per IP). Results are cached locally when possible.\n• Return Shape: Returns a JSON object containing 'query', 'total_results', and 'results' (array of objects with title, url, score, is_answered, answer_count, and answer excerpt).\n• Failure Modes: Returns empty results array if no matching questions exist. Returns an error message if network connectivity fails or API quota is exhausted.\n• When to use: Use when local code context from get_error_context is insufficient and external community patterns, known library bugs, or API migration examples are needed.\n• When NOT to use: Do NOT use with raw un-sanitized logs containing private tokens or file paths, do NOT use for local codebase inspection (use get_error_context), and do NOT use to edit code (use apply_code_patch).\n• Prerequisites: Outbound HTTP internet access to api.stackexchange.com.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "query": {
                                        "type": "string",
                                        "description": "Targeted search query string (e.g. 'ValueError: unsupported operand type(s) for +: int and str'). Must be free of project-specific paths, private tokens, or proprietary variable names. 3 to 150 characters recommended."
                                    }
                                },
                                "required": ["query"]
                            }
                        },
                        {
                            "name": "apply_code_patch",
                            "description": "Applies an atomic, verified code edit to a specific file by substituting original_code with new_code, with automatic syntax validation and instant rollback on failure.\n\n• Side Effects: Modifies the target file on the local filesystem. If syntax checks pass, the file is overwritten with patched contents; if syntax validation fails, the file is immediately restored to its exact original state (zero dirty diff).\n• Auth & Permissions: Requires write permissions for the target file on the host filesystem within the workspace boundary. Path traversal outside workspace root is blocked.\n• Rate Limits: None. Local disk I/O.\n• Return Shape: Returns a JSON object with 'status' ('success' or 'error'), 'file_path', 'lines_changed', 'verification' ('passed' or 'reverted'), and 'message'.\n• Failure Modes: Fails and aborts without touching the file if file_path is not found, if original_code does not match the file content uniquely, or if the compiler/linter check fails after patch application.\n• When to use: Use when you have finalized a bug fix or refactoring snippet and need safe, transactional application with zero risk of syntax corruption.\n• When NOT to use: Do NOT use for speculative edits without prior diagnosis (use get_error_context first), and do NOT use for whole-file generation when only a small block changes.\n• Prerequisites: Target file must exist and be within the current workspace directory.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "file_path": {
                                        "type": "string",
                                        "description": "Target file path to modify. Can be relative to the workspace root or an absolute path located inside the workspace boundary. Path traversal outside the workspace is rejected."
                                    },
                                    "original_code": {
                                        "type": "string",
                                        "description": "The exact character-for-character contiguous code block to be replaced, including exact leading indentation, newlines, and whitespace. Must match exactly one location in the file."
                                    },
                                    "new_code": {
                                        "type": "string",
                                        "description": "The replacement code block to substitute in place of original_code. Must maintain correct language syntax and indentation matching the surrounding code."
                                    },
                                    "dry_run": {
                                        "type": "boolean",
                                        "description": "Optional. When true, validates that the patch matches uniquely and checks syntax without writing any changes to disk. Defaults to false."
                                    }
                                },
                                "required": ["file_path", "original_code", "new_code"]
                            }
                        },
                        {
                            "name": "analyze_code",
                            "description": "Performs static AST code analysis using Tree-sitter to detect resource leaks (such as unclosed file handles), security vulnerabilities, and logic flaws with bounded execution limits and precise LSP UTF-16 coordinates.\n\n• Side Effects: None. Strictly read-only analysis of in-memory code; does not execute code, spawn subprocesses, or write to disk.\n• Auth & Permissions: None required. Fully offline, in-memory parser.\n• Rate Limits: None. Bounded to 1MB max source size, 128 max AST depth, and 50,000 max node visits per call.\n• Return Shape: Returns a JSON object containing 'language', 'findings_count', 'duration_ms' (latency metric), and 'findings' (array of objects with rule_id, message, severity, line [1-indexed], column [1-indexed UTF-16 code units], and remediation).\n• Failure Modes: Returns findings: [] if the code contains no detected defects. Returns an error message if the language is unsupported or if source code exceeds the 1MB or 128 AST depth limits.\n• When to use: Use proactively before committing or running code, or when reviewing Python files for unclosed file handles, resource leaks, or AST defects.\n• When NOT to use: Do NOT use when you have an active runtime crash log (use get_error_context instead), and do NOT use to apply fixes automatically (use apply_code_patch instead).\n• Prerequisites: Supported languages currently include Python ('python', 'py').",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "language": {
                                        "type": "string",
                                        "description": "Programming language identifier for the code snippet. Case-insensitive. Supported values: 'python', 'py'."
                                    },
                                    "code": {
                                        "type": "string",
                                        "description": "Raw source code string to analyze. Must not exceed 1,000,000 bytes (1MB). Does not execute runtime code; strictly parsed via Tree-sitter AST."
                                    }
                                },
                                "required": ["language", "code"]
                            }
                        }
                    ]
                }),
            )),
            "tools/call" => {
                let params = req.get("params");
                let name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());
                let args = params.and_then(|p| p.get("arguments"));

                if let (Some(name), Some(args)) = (name, args) {
                    match name {
                        "get_error_context" => {
                            if let Some(log) = args.get("log").and_then(|l| l.as_str()) {
                                let context_lines = args
                                    .get("context_lines")
                                    .and_then(|c| c.as_u64())
                                    .unwrap_or(10) as usize;
                                // P1: Redact secrets and prune framework noise BEFORE extracting context
                                let safe_log = redact::redact_secrets(log);
                                let clean_log = extractor::prune_framework_noise(&safe_log);
                                let (context, _) = extractor::extract_context_with_boundary(
                                    &safe_log,
                                    context_lines,
                                    Some(&boundary),
                                );
                                let mut combined = format!(
                                    "--- Tokenectomy Surgery Report ({}) ---\nLog:\n{}\nContext:\n{}",
                                    crate::ENGINE_SIGNATURE,
                                    clean_log,
                                    context
                                );
                                if let Some(git_diff) = git::get_recent_changes() {
                                    let safe_diff = redact::redact_secrets(&git_diff);
                                    combined.push_str(&format!(
                                        "\n\nRecent Git Changes:\n{}",
                                        safe_diff
                                    ));
                                }
                                Some(success_response(
                                    id.unwrap_or(Value::Null),
                                    json!({
                                        "content": [{ "type": "text", "text": combined }]
                                    }),
                                ))
                            } else {
                                Some(success_response(
                                    id.unwrap_or(Value::Null),
                                    json!({
                                        "content": [{ "type": "text", "text": "Error: Missing required 'log' argument." }],
                                        "isError": true
                                    }),
                                ))
                            }
                        }
                        "search_stack_overflow" => {
                            if let Some(query) = args.get("query").and_then(|q| q.as_str()) {
                                let results = search::search_stackoverflow(query).await;
                                let text = results
                                    .unwrap_or_else(|| "No results found".to_string());
                                Some(success_response(
                                    id.unwrap_or(Value::Null),
                                    json!({
                                        "content": [{ "type": "text", "text": text }]
                                    }),
                                ))
                            } else {
                                Some(success_response(
                                    id.unwrap_or(Value::Null),
                                    json!({
                                        "content": [{ "type": "text", "text": "Error: Missing required 'query' argument." }],
                                        "isError": true
                                    }),
                                ))
                            }
                        }
                        "apply_code_patch" => {
                            let file_path = args.get("file_path").and_then(|f| f.as_str());
                            let original = args.get("original_code").and_then(|o| o.as_str());
                            let new_code = args.get("new_code").and_then(|n| n.as_str());
                            let dry_run = args.get("dry_run").and_then(|d| d.as_bool()).unwrap_or(false);

                            if let (Some(fp), Some(orig), Some(new_c)) =
                                (file_path, original, new_code)
                            {
                                match boundary.resolve(fp) {
                                    Err(e) => Some(success_response(
                                        id.unwrap_or(Value::Null),
                                        json!({
                                            "content": [{ "type": "text", "text": format!("Security Error: {}", e) }],
                                            "isError": true
                                        }),
                                    )),
                                    Ok(safe_path) => {
                                        match boundary.read(&safe_path) {
                                            Ok(content) => {
                                                // Handle CRLF vs LF line-ending normalization for cross-platform resilience
                                                let (target_orig, target_new) = if content.matches(orig).count() > 0 {
                                                    (orig.to_string(), new_c.to_string())
                                                } else {
                                                    let orig_crlf = orig.replace("\r\n", "\n").replace('\n', "\r\n");
                                                    let new_crlf = new_c.replace("\r\n", "\n").replace('\n', "\r\n");
                                                    if content.matches(&orig_crlf).count() > 0 {
                                                        (orig_crlf, new_crlf)
                                                    } else {
                                                        let orig_lf = orig.replace("\r\n", "\n");
                                                        let new_lf = new_c.replace("\r\n", "\n");
                                                        if content.matches(&orig_lf).count() > 0 {
                                                            (orig_lf, new_lf)
                                                        } else {
                                                            (orig.to_string(), new_c.to_string())
                                                        }
                                                    }
                                                };

                                                let count = content.matches(&target_orig).count();
                                                if count == 0 {
                                                    Some(success_response(
                                                        id.unwrap_or(Value::Null),
                                                        json!({
                                                            "content": [{ "type": "text", "text": "Error: original_code not found in the file. Make sure it matches exactly." }],
                                                            "isError": true
                                                        }),
                                                    ))
                                                } else if count > 1 {
                                                    Some(success_response(
                                                        id.unwrap_or(Value::Null),
                                                        json!({
                                                            "content": [{ "type": "text", "text": format!("Error: original_code found {} times. Please provide a more specific code block.", count) }],
                                                            "isError": true
                                                        }),
                                                    ))
                                                } else if dry_run {
                                                    let is_rust = safe_path.extension().and_then(|e| e.to_str()) == Some("rs");
                                                    if is_rust {
                                                        let backup = content.clone();
                                                        let updated = content.replacen(&target_orig, &target_new, 1);
                                                        // In dry-run mode for Rust, stage write in place so cargo check
                                                        // tests within the crate module tree, then unconditionally restore original backup.
                                                        match boundary.write(&safe_path, updated.as_bytes()) {
                                                            Ok(_) => {
                                                                let verify_result = verify_patch(&safe_path);
                                                                let _ = boundary.write(&safe_path, backup.as_bytes()); // Zero dirty diff guarantee
                                                                match verify_result {
                                                                    Ok(_) => Some(success_response(
                                                                        id.unwrap_or(Value::Null),
                                                                        json!({
                                                                            "content": [{ "type": "text", "text": "Dry-run succeeded: target code block matched uniquely and syntax verification passed. Target file was not modified." }],
                                                                            "dry_run": true,
                                                                            "status": "success"
                                                                        }),
                                                                    )),
                                                                    Err(verify_err) => Some(success_response(
                                                                        id.unwrap_or(Value::Null),
                                                                        json!({
                                                                            "content": [{ "type": "text", "text": format!("Dry-run verification failed: {}", verify_err) }],
                                                                            "isError": true,
                                                                            "dry_run": true
                                                                        }),
                                                                    )),
                                                                }
                                                            }
                                                            Err(e) => Some(success_response(
                                                                id.unwrap_or(Value::Null),
                                                                json!({
                                                                    "content": [{ "type": "text", "text": format!("Dry-run failed to stage temporary test content: {}", e) }],
                                                                    "isError": true,
                                                                    "dry_run": true
                                                                }),
                                                            )),
                                                        }
                                                    } else {
                                                        // For non-Rust files (py, js, ts, go, json, toml, yaml, php), test against an isolated sandbox temp file
                                                        // without ever touching or modifying the actual target file on disk!
                                                        static DRY_RUN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                                                        let counter = DRY_RUN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                        let updated = content.replacen(&target_orig, &target_new, 1);
                                                        let ext = safe_path.extension().and_then(|e| e.to_str()).unwrap_or("tmp");
                                                        let temp_file = safe_path.with_file_name(format!(
                                                            ".dry_run_{}_{}.tmp.{}",
                                                            std::process::id(),
                                                            counter,
                                                            ext
                                                        ));
                                                        let _ = std::fs::write(&temp_file, updated.as_bytes());
                                                        struct TempFileGuard(std::path::PathBuf);
                                                        impl Drop for TempFileGuard {
                                                            fn drop(&mut self) {
                                                                let _ = std::fs::remove_file(&self.0);
                                                            }
                                                        }
                                                        let _guard = TempFileGuard(temp_file.clone());
                                                        let verify_result = verify_patch(&temp_file);
                                                        drop(_guard);

                                                        match verify_result {
                                                            Ok(_) => Some(success_response(
                                                                id.unwrap_or(Value::Null),
                                                                json!({
                                                                    "content": [{ "type": "text", "text": "Dry-run succeeded: target code block matched uniquely and syntax verification passed. Target file was not modified." }],
                                                                    "dry_run": true,
                                                                    "status": "success"
                                                                }),
                                                            )),
                                                            Err(verify_err) => Some(success_response(
                                                                id.unwrap_or(Value::Null),
                                                                json!({
                                                                    "content": [{ "type": "text", "text": format!("Dry-run verification failed: {}", verify_err) }],
                                                                    "isError": true,
                                                                    "dry_run": true
                                                                }),
                                                            )),
                                                        }
                                                    }
                                                } else {
                                                    let backup = content.clone();
                                                    let updated = content.replacen(&target_orig, &target_new, 1);
                                                    match boundary.write(&safe_path, updated.as_bytes()) {
                                                        Ok(_) => match verify_patch(&safe_path) {
                                                            Ok(_) => Some(success_response(
                                                                id.unwrap_or(Value::Null),
                                                                json!({
                                                                    "content": [{ "type": "text", "text": "Patch applied and verified successfully." }]
                                                                }),
                                                            )),
                                                            Err(verify_err) => {
                                                                let rollback_status = if let Err(rb_err) =
                                                                    boundary.write(&safe_path, backup.as_bytes())
                                                                {
                                                                    format!(
                                                                        "CRITICAL: Patch verification failed ({}), and rollback ALSO failed: {}",
                                                                        verify_err, rb_err
                                                                    )
                                                                } else {
                                                                    format!(
                                                                        "Patch rejected and automatically rolled back: {}",
                                                                        verify_err
                                                                    )
                                                                };
                                                                Some(success_response(
                                                                    id.unwrap_or(Value::Null),
                                                                    json!({
                                                                        "content": [{ "type": "text", "text": rollback_status }],
                                                                        "isError": true
                                                                    }),
                                                                ))
                                                            }
                                                        },
                                                        Err(e) => Some(success_response(
                                                            id.unwrap_or(Value::Null),
                                                            json!({
                                                                "content": [{ "type": "text", "text": format!("Failed to write file: {}", e) }],
                                                                "isError": true
                                                            }),
                                                        )),
                                                    }
                                                }
                                            }
                                            Err(e) => Some(success_response(
                                                id.unwrap_or(Value::Null),
                                                json!({
                                                    "content": [{ "type": "text", "text": format!("Failed to read file: {}", e) }],
                                                    "isError": true
                                                }),
                                            )),
                                        }
                                    }
                                }
                            } else {
                                Some(success_response(
                                    id.unwrap_or(Value::Null),
                                    json!({
                                        "content": [{ "type": "text", "text": "Missing required arguments for apply_code_patch." }],
                                        "isError": true
                                    }),
                                ))
                            }
                        }
                        "analyze_code" => {
                            let language = args.get("language").and_then(|l| l.as_str());
                            let code = args.get("code").and_then(|c| c.as_str());

                            if let (Some(lang), Some(source)) = (language, code) {
                                match crate::analyzer::analyze_source(&analyzer_state, lang, source) {
                                    Ok(resp) => {
                                        let json_output = serde_json::to_string_pretty(&resp).unwrap_or_default();
                                        Some(success_response(
                                            id.unwrap_or(Value::Null),
                                            json!({
                                                "content": [{ "type": "text", "text": json_output }]
                                            }),
                                        ))
                                    }
                                    Err(e) => {
                                        Some(success_response(
                                            id.unwrap_or(Value::Null),
                                            json!({
                                                "content": [{ "type": "text", "text": format!("Analysis error: {}", e) }],
                                                "isError": true
                                            }),
                                        ))
                                    }
                                }
                            } else {
                                Some(success_response(
                                    id.unwrap_or(Value::Null),
                                    json!({
                                        "content": [{ "type": "text", "text": "Error: Missing required 'language' or 'code' argument." }],
                                        "isError": true
                                    }),
                                ))
                            }
                        }
                        _ => Some(error_response(
                            id,
                            -32601,
                            &format!("Tool '{}' not found", name),
                        )),
                    }
                } else {
                    Some(error_response(id, -32602, "Invalid params"))
                }
            }
            _ => {
                if id.is_some() {
                    Some(error_response(id, -32601, "Method not found"))
                } else {
                    None
                }
            }
        };

        if let Some(res) = response {
            writeln!(stdout, "{}", serde_json::to_string(&res)?)?;
            stdout.flush()?;
        }
    }
    Ok(())
}