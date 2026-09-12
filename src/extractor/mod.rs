pub mod python;
pub mod js;
pub mod rust;
pub mod go;
pub mod java;
pub mod cpp;
pub mod php;
pub mod csharp;
pub mod ruby;

pub struct CodeLocation {
    pub file: String,
    pub line: usize,
}

pub trait TraceParser: Send + Sync {
    fn detect(&self, log: &str) -> bool;
    fn extract_locations(&self, log: &str) -> Vec<CodeLocation>;
}

/// Checks whether `component` appears in `text` enclosed by path or word boundaries
/// (e.g. '/', '\', whitespace, quotes, parentheses, colon).
/// Prevents false positives like 'vendor_portal' matching 'vendor', or 'chicago/src' matching 'go/src'.
pub fn has_path_component(text: &str, component: &str) -> bool {
    let bytes = text.as_bytes();
    let comp_bytes = component.as_bytes();
    if comp_bytes.is_empty() || bytes.len() < comp_bytes.len() {
        return false;
    }

    let is_boundary = |b: u8| -> bool {
        b == b'/'
            || b == b'\\'
            || b == b' '
            || b == b'\t'
            || b == b'"'
            || b == b'\''
            || b == b'('
            || b == b')'
            || b == b'['
            || b == b']'
            || b == b':'
            || b == b'\r'
            || b == b'\n'
    };

    let mut start = 0;
    while let Some(pos) = text[start..].find(component) {
        let idx = start + pos;
        let before_ok = if idx == 0 {
            true
        } else {
            is_boundary(bytes[idx - 1])
        };

        let after_idx = idx + comp_bytes.len();
        let after_ok = if after_idx == bytes.len() {
            true
        } else {
            is_boundary(bytes[after_idx])
        };

        if before_ok && after_ok {
            return true;
        }

        start = idx + 1;
    }

    false
}

/// Determines whether a file path or stack trace line represents framework, runtime, or dependency noise.
pub fn is_framework_noise(line_or_path: &str) -> bool {
    let lower = line_or_path.to_lowercase();
    let trimmed = line_or_path.trim_start();
    let path_norm = lower.replace('\\', "/");

    // 1. Exact path directory component matches (prevents false positives on 'vendor_portal', 'chicago/src', 'inventory')
    let component_ignores = [
        "node_modules",        // JS/Node/TS
        "site-packages",       // Python
        "dist-packages",       // Python
        "venv",                // Python VirtualEnv
        ".venv",               // Python VirtualEnv
        "vendor",              // PHP/Go/Ruby dependencies
        "gems",                // Ruby gems
        "__pycache__",          // Python compiled bytecode
        "vcpkg_installed",     // C++ vcpkg
        ".gradle",             // Java Gradle cache
        ".cargo/registry",     // Rust
        ".rustup",             // Rust toolchain
        "pkg/mod",             // Go modules cache
        "go/src",              // Go standard library
        ".m2/repository",      // Java Maven repo
        "usr/include",         // C/C++ system headers
        "usr/lib",             // C/C++ system libraries
        "target/debug/build",  // Rust build scripts
        "lib/python",          // Python built-ins
        "internal/modules",    // Node.js internal CJS/ESM loader
        "rustc",               // Rust standard library / compiler frames
    ];

    for ignore in component_ignores.iter() {
        if has_path_component(&path_norm, ignore) {
            return true;
        }
    }

    // 2. Specific runtime protocol prefixes and markers
    let runtime_markers = [
        "node:internal/",      // Node.js internal runtime
        "<frozen ",            // Python internal frozen modules & importlib
        "asyncio/base_events", // Python asyncio internals
        "asyncio/events.py",   // Python asyncio internals
        "starlette/routing",   // Starlette / FastAPI routing frames
        "uvicorn/protocols/",  // Uvicorn server frames
        "gunicorn/workers/",   // Gunicorn worker frames
        "build/glibc-",        // Glibc internals
        "system.private.corelib", // .NET CoreLib
        "microsoft.aspnetcore.",  // ASP.NET Core
    ];

    for marker in runtime_markers.iter() {
        if path_norm.contains(marker) {
            return true;
        }
    }

    // 2. Java / Kotlin enterprise framework stack frames (Spring Boot, Tomcat, Hibernate, Netty, Undertow, JDK)
    let java_framework_prefixes = [
        "at org.springframework.",
        "at org.apache.catalina.",
        "at org.apache.tomcat.",
        "at org.apache.coyote.",
        "at org.hibernate.",
        "at org.eclipse.jetty.",
        "at jakarta.servlet.",
        "at javax.servlet.",
        "at io.netty.",
        "at io.undertow.",
        "at com.zaxxer.hikari.",
        "at java.base/",
        "at java.lang.reflect.",
        "at jdk.internal.",
        "at sun.reflect.",
        "at kotlinx.coroutines.",
        "at org.junit.",
        "at System.",
        "at Microsoft.AspNetCore.",
    ];
    for prefix in java_framework_prefixes.iter() {
        if trimmed.starts_with(prefix) {
            return true;
        }
    }
    if trimmed.starts_with("... ") && trimmed.ends_with("common frames omitted") {
        return true;
    }

    // 3. C / C++ ASan, GDB, glibc, libstdc++ runtime frames
    let cpp_runtime_markers = [
        "__libc_start_main",
        "__libc_start_call_main",
        "libc-start.c",
        "libc_start_call_main.h",
        "/lib/x86_64-linux-gnu/libc.so",
        "/lib/x86_64-linux-gnu/libasan.so",
        "/usr/lib/x86_64-linux-gnu/libasan.so",
        "/usr/lib/x86_64-linux-gnu/libstdc++.so",
        "libasan.so",
        "libstdc++.so",
        "__sanitizer::",
        "__asan::",
        "__asan_",
        "(/lib/x86_64-linux-gnu/",
        "(/usr/lib/x86_64-linux-gnu/",
        "sysdeps/nptl/",
    ];
    for marker in cpp_runtime_markers.iter() {
        if line_or_path.contains(marker) {
            return true;
        }
    }
    if trimmed.contains(" in _start (") || trimmed.ends_with(" in _start") {
        return true;
    }

    // 4. Go runtime goroutine idle states & internal scheduler frames
    let go_idle_markers = [
        "[force gc (idle)]",
        "[GC sweep wait]",
        "[GC scavenge wait]",
        "[finalizer wait]",
        "[scavenge wait]",
        "[select (no cases)]",
    ];
    for marker in go_idle_markers.iter() {
        if line_or_path.contains(marker) {
            return true;
        }
    }

    let go_runtime_frames = [
        "runtime.gopark(",
        "runtime.forcegchelper(",
        "runtime.goexit(",
        "runtime.gcBgMarkWorker(",
        "runtime.bgsweep(",
        "runtime.bgscavenge(",
        "runtime.runfinq(",
    ];
    for frame in go_runtime_frames.iter() {
        if trimmed.starts_with(frame) {
            return true;
        }
    }

    false
}

/// Backward-compatible parallel-bridge shim for `is_dependency_file`.
/// Retains 100% compatibility with existing callers while delegating to `is_framework_noise`.
#[inline]
pub fn is_dependency_file(path: &str) -> bool {
    is_framework_noise(path)
}

/// Checks if a line or path is framework noise, incorporating user-defined custom patterns.
pub fn is_framework_noise_with_custom(line_or_path: &str, custom_noise: &[String]) -> bool {
    if is_framework_noise(line_or_path) {
        return true;
    }
    let lower = line_or_path.to_lowercase();
    for pat in custom_noise {
        if !pat.is_empty() && lower.contains(&pat.to_lowercase()) {
            return true;
        }
    }
    false
}

/// Surgically prunes framework noise, internal runtime stack lines, and idle Go goroutines from a raw log.
pub fn prune_framework_noise(raw: &str) -> String {
    prune_framework_noise_with_custom(raw, &[])
}

/// Surgically prunes framework noise including user-defined custom noise patterns.
pub fn prune_framework_noise_with_custom(raw: &str, custom_noise: &[String]) -> String {
    let mut cleaned_lines = Vec::new();
    let mut in_idle_goroutine = false;

    for line in raw.lines() {
        let trimmed = line.trim();

        // Detect Go goroutine block headers
        if trimmed.starts_with("goroutine ") {
            if trimmed.contains("[force gc (idle)]")
                || trimmed.contains("[GC sweep wait]")
                || trimmed.contains("[GC scavenge wait]")
                || trimmed.contains("[finalizer wait]")
                || trimmed.contains("[scavenge wait]")
                || trimmed.contains("[select (no cases)]")
            {
                in_idle_goroutine = true;
                continue;
            } else {
                in_idle_goroutine = false;
            }
        }

        // If inside an idle goroutine, skip lines until next non-indented block or empty line
        if in_idle_goroutine {
            if line.is_empty() {
                in_idle_goroutine = false;
            }
            continue;
        }

        // Check if the individual line is framework noise
        if is_framework_noise_with_custom(line, custom_noise) {
            continue;
        }

        cleaned_lines.push(line);
    }

    cleaned_lines.join("\n")
}

pub fn extract_context(log: &str, context_lines: usize, strict_cwd: bool) -> (String, Vec<String>) {
    let boundary = if strict_cwd {
        crate::workspace::WorkspaceBoundary::current().ok()
    } else {
        None
    };
    extract_context_with_boundary(log, context_lines, boundary.as_ref())
}

pub fn extract_context_with_boundary(
    log: &str,
    context_lines: usize,
    boundary: Option<&crate::workspace::WorkspaceBoundary>,
) -> (String, Vec<String>) {
    let parsers: Vec<Box<dyn TraceParser>> = vec![
        Box::new(rust::RustTraceParser),
        Box::new(python::PythonTraceParser),
        Box::new(js::JsTraceParser),
        Box::new(go::GoTraceParser),
        Box::new(java::JavaTraceParser),
        Box::new(cpp::CppTraceParser),
        Box::new(php::PhpTraceParser),
        Box::new(csharp::CSharpTraceParser),
        Box::new(ruby::RubyTraceParser),
    ];

    let mut context_output = String::new();
    let mut extracted_files = Vec::new();
    let mut seen_locations: std::collections::HashSet<(String, usize)> = std::collections::HashSet::new();

    for parser in parsers {
        if parser.detect(log) {
            let locations = parser.extract_locations(log);
            for loc in locations {
                // Deduplicate across polyglot parsers and repetitive trace frames
                if !seen_locations.insert((loc.file.clone(), loc.line)) {
                    continue;
                }

                // Filter cerdas: Abaikan file internal framework/library/dependency
                if is_dependency_file(&loc.file) {
                    log::debug!("Ignoring framework/dependency file: {}", loc.file);
                    continue;
                }

                // Security: Strict boundary check
                if let Some(b) = boundary {
                    if !b.is_safe(&loc.file) {
                        log::debug!("Security Block: File outside workspace boundary ignored: {}", loc.file);
                        continue;
                    }
                }

                let content_opt = if let Some(b) = boundary {
                    b.read(&loc.file).ok()
                } else {
                    std::fs::read_to_string(&loc.file).ok()
                };

                if let Some(content) = content_opt {
                    if !extracted_files.contains(&loc.file) {
                        extracted_files.push(loc.file.clone());
                    }
                    
                    let lines: Vec<&str> = content.lines().collect();
                    let start = loc.line.saturating_sub(context_lines).saturating_sub(1);
                    let end = (loc.line + context_lines).min(lines.len());
                    
                    context_output.push_str(&format!("--- {} (Lines {}-{}) ---\n", loc.file, start + 1, end));
                    for (i, line) in lines.iter().enumerate().take(end).skip(start) {
                        context_output.push_str(&format!("{} | {}\n", i + 1, line));
                    }
                    context_output.push_str("\n");
                }
            }
        }
    }

    (context_output, extracted_files)
}
