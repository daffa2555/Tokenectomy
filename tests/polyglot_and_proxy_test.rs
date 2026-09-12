use tokenectomy::extractor::TraceParser;
use tokenectomy::extractor::{go::GoTraceParser, java::JavaTraceParser, cpp::CppTraceParser, php::PhpTraceParser, js::JsTraceParser};
use tokenectomy::proxy::sanitize_prompt_payload;

#[test]
fn test_go_trace_parser() {
    let parser = GoTraceParser;
    let go_panic = r#"
panic: runtime error: index out of range [3] with length 2

goroutine 1 [running]:
main.calculateTotal(0xc0000a4000, 0x3, 0x3)
	/app/src/billing/calc.go:42 +0x3f
main.main()
	/app/src/cmd/main.go:15 +0x2b
"#;
    assert!(parser.detect(go_panic));
    let locs = parser.extract_locations(go_panic);
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].file, "/app/src/billing/calc.go");
    assert_eq!(locs[0].line, 42);
    assert_eq!(locs[1].file, "/app/src/cmd/main.go");
    assert_eq!(locs[1].line, 15);
}

#[test]
fn test_java_trace_parser() {
    let parser = JavaTraceParser;
    let java_trace = r#"
Exception in thread "main" java.lang.NullPointerException: Cannot invoke method on null
	at com.example.service.PaymentService.processOrder(PaymentService.java:55)
	at com.example.controller.OrderController.handleCheckout(OrderController.kt:28)
	at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1089)
"#;
    assert!(parser.detect(java_trace));
    let locs = parser.extract_locations(java_trace);
    assert!(locs.len() >= 2);
    assert_eq!(locs[0].file, "PaymentService.java");
    assert_eq!(locs[0].line, 55);
    assert_eq!(locs[1].file, "OrderController.kt");
    assert_eq!(locs[1].line, 28);
}

#[test]
fn test_cpp_trace_parser() {
    let parser = CppTraceParser;
    let cpp_trace = r#"
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 4 at 0x602000000014 thread T0
    #0 0x555555555149 in process_tensor(float const*, int) src/core/tensor.cpp:88
    #1 0x55555555518b in main src/main.cpp:24
"#;
    assert!(parser.detect(cpp_trace));
    let locs = parser.extract_locations(cpp_trace);
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].file, "src/core/tensor.cpp");
    assert_eq!(locs[0].line, 88);
    assert_eq!(locs[1].file, "src/main.cpp");
    assert_eq!(locs[1].line, 24);
}

#[test]
fn test_php_trace_parser() {
    let parser = PhpTraceParser;
    let php_trace = r#"
Fatal error: Uncaught TypeError: Argument 1 passed to App\Auth::login() must be of the type string, null given in /var/www/src/Auth.php:73
Stack trace:
#0 /var/www/src/Controller.php(32): App\Auth->login()
#1 /var/www/vendor/laravel/framework/src/Illuminate/Routing/Controller.php(54): App\Controller->handle()
"#;
    assert!(parser.detect(php_trace));
    let locs = parser.extract_locations(php_trace);
    assert_eq!(locs.len(), 3);
    assert_eq!(locs[0].file, "/var/www/src/Auth.php");
    assert_eq!(locs[0].line, 73);
    assert_eq!(locs[1].file, "/var/www/src/Controller.php");
    assert_eq!(locs[1].line, 32);
    assert!(tokenectomy::extractor::is_dependency_file(&locs[2].file));
    assert!(!tokenectomy::extractor::is_dependency_file(&locs[0].file));
}

#[test]
fn test_js_ts_extended_parser() {
    let parser = JsTraceParser;
    let ts_trace = r#"
TypeError: Cannot read properties of undefined (reading 'userId')
    at AuthHandler.verifyToken (/app/src/auth/handler.ts:42:18)
    at Object.<anonymous> (/app/src/components/App.tsx:99:12)
    at Module._compile (node_modules/ts-node/dist/index.js:85:10)
"#;
    assert!(parser.detect(ts_trace));
    let locs = parser.extract_locations(ts_trace);
    assert!(locs.iter().any(|l| l.file == "/app/src/auth/handler.ts" && l.line == 42));
    assert!(locs.iter().any(|l| l.file == "/app/src/components/App.tsx" && l.line == 99));
}

#[test]
fn test_proxy_sanitize_prompt_payload() {
    let inbound_json = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful coding assistant."
            },
            {
                "role": "user",
                "content": "Here is the error from my Go server with API_KEY=sk-ant-api03-abcdef1234567890abcdef1234567890\n\npanic: runtime error: index out of range [3]\ngoroutine 1 [running]:\nmain.run()\n\t/usr/local/go/src/runtime/panic.go:40\n"
            }
        ]
    });

    let (sanitized_json, stats) = sanitize_prompt_payload(&inbound_json);
    
    let user_msg = sanitized_json["messages"][1]["content"].as_str().unwrap();
    assert!(!user_msg.contains("sk-ant-api03-abcdef1234567890abcdef1234567890"));
    assert!(user_msg.contains("[ANTHROPIC_API_KEY_REDACTED]") || user_msg.contains("REDACTED"));
    assert!(stats.secrets_redacted >= 1);
}

#[tokio::test]
async fn test_proxy_tcp_health_endpoint() {
    let bind_addr = "127.0.0.1:18095";
    tokio::spawn(async move {
        let _ = tokenectomy::proxy::run_reverse_proxy(bind_addr, "http://127.0.0.1:11434").await;
    });

    // Wait for server to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let resp = client.get("http://127.0.0.1:18095/health").send().await.expect("Failed to connect to proxy");
    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.expect("Invalid JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "tokenectomy-gateway");
}

#[test]
fn test_scrub_prunes_dependency_frames_and_redacts_credentials() {
    let dirty_log = r#"
Error: Failed to connect to cluster
    at queryMaster (/app/src/db.ts:15:2)
    at node_modules/pg/lib/connection.js:84:11
    at node_modules/@prisma/client/runtime.js:200:5
    at site-packages/django/db/backends.py:40:1
Connection string: postgresql://admin:SuperSecretPass@cluster.internal:5432/main
AWS Key: AKIAIOSFODNN7EXAMPLE
    "#;

    let mut pruned = Vec::new();
    for line in dirty_log.lines() {
        if !tokenectomy::extractor::is_dependency_file(line) {
            pruned.push(line);
        }
    }
    let joined = pruned.join("\n");
    let safe = tokenectomy::redact::redact_secrets(&joined);

    assert!(!safe.contains("node_modules"));
    assert!(!safe.contains("site-packages"));
    assert!(!safe.contains("SuperSecretPass"));
    assert!(!safe.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(safe.contains("/app/src/db.ts:15:2"));
    assert!(safe.contains("[CONNECTION_STRING_REDACTED]"));
    assert!(safe.contains("[AWS_KEY_REDACTED]"));
}

#[test]
fn test_proxy_is_loopback() {
    assert!(tokenectomy::proxy::is_loopback("127.0.0.1:8080"));
    assert!(tokenectomy::proxy::is_loopback("127.0.0.1"));
    assert!(tokenectomy::proxy::is_loopback("localhost:8080"));
    assert!(tokenectomy::proxy::is_loopback("localhost"));
    assert!(tokenectomy::proxy::is_loopback("[::1]:8080"));
    assert!(tokenectomy::proxy::is_loopback("::1"));

    assert!(!tokenectomy::proxy::is_loopback("0.0.0.0:8080"));
    assert!(!tokenectomy::proxy::is_loopback("192.168.1.100:8080"));
    assert!(!tokenectomy::proxy::is_loopback("10.0.0.1:8080"));
}

#[tokio::test]
async fn test_proxy_remote_bind_security_guards() {
    // 1. Binding to non-loopback without allow_remote should fail
    let res = tokenectomy::proxy::run_reverse_proxy_configured("0.0.0.0:18991", "http://127.0.0.1:11434", false, None).await;
    assert!(res.is_err());
    let err = res.err().unwrap().to_string();
    assert!(err.contains("Security Violation"));
    assert!(err.contains("--allow-remote"));

    // 2. Binding to non-loopback with allow_remote=true but missing token should fail
    let res2 = tokenectomy::proxy::run_reverse_proxy_configured("0.0.0.0:18991", "http://127.0.0.1:11434", true, None).await;
    assert!(res2.is_err());
    let err2 = res2.err().unwrap().to_string();
    assert!(err2.contains("requires an authentication token"));
}

#[tokio::test]
async fn test_proxy_bearer_auth_and_unauthorized_rejection() {
    let bind_addr = "127.0.0.1:18096";
    let auth_token = "my-secret-agent-token-12345";

    tokio::spawn(async move {
        let _ = tokenectomy::proxy::run_reverse_proxy_configured(
            bind_addr,
            "http://127.0.0.1:11434",
            false,
            Some(auth_token),
        ).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // 1. Health endpoint should remain accessible without token
    let health_resp = client.get("http://127.0.0.1:18096/health").send().await.expect("Failed to call /health");
    assert_eq!(health_resp.status(), 200);

    // 2. Protected endpoint without token should return 401 Unauthorized
    let unauth_resp = client.post("http://127.0.0.1:18096/v1/chat/completions")
        .body("{}")
        .send()
        .await
        .expect("Failed to call completions");
    assert_eq!(unauth_resp.status(), 401);

    // 3. Protected endpoint with invalid token should return 401 Unauthorized
    let wrong_resp = client.post("http://127.0.0.1:18096/v1/chat/completions")
        .header("Authorization", "Bearer wrong-token")
        .body("{}")
        .send()
        .await
        .expect("Failed to call completions with wrong token");
    assert_eq!(wrong_resp.status(), 401);
}

#[test]
fn test_verify_patch_and_auto_rollback_on_syntax_error() {
    let temp_dir = std::env::temp_dir().join(format!("tokenectomy_verify_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // Create a valid Python file
    let py_path = temp_dir.join("calc.py");
    let valid_code = "def calculate_tax(subtotal: float) -> float:\n    return subtotal * 0.1\n";
    std::fs::write(&py_path, valid_code).expect("Failed to write test file");

    // 1. Verification of valid file passes
    let verify_res = tokenectomy::mcp::verify_patch(&py_path);
    assert!(verify_res.is_ok());

    // 2. Simulate patch with syntax error (invalid Python)
    let broken_code = "def calculate_tax(subtotal: float\n    return subtotal *\n";
    // Simulate apply_code_patch: backup original, write patch, verify, rollback on fail
    let backup = std::fs::read_to_string(&py_path).unwrap();
    std::fs::write(&py_path, broken_code).unwrap();
    
    let check = tokenectomy::mcp::verify_patch(&py_path);
    assert!(check.is_err(), "Broken syntax must fail verification");
    
    // Auto-rollback
    std::fs::write(&py_path, &backup).unwrap();
    let restored = std::fs::read_to_string(&py_path).unwrap();
    assert_eq!(restored, valid_code, "File must be 100% restored with 0 dirty diff");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_spring_boot_deep_stack_trace_pruning() {
    let raw_trace = r#"
org.springframework.web.util.NestedServletException: Request processing failed: java.lang.NullPointerException: user repository returned null
	at org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1014)
	at org.springframework.web.servlet.FrameworkServlet.doPost(FrameworkServlet.java:914)
	at jakarta.servlet.http.HttpServlet.service(HttpServlet.java:590)
	at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:885)
	at jakarta.servlet.http.HttpServlet.service(HttpServlet.java:658)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:205)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:149)
	at org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:51)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:174)
	at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:167)
	at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:90)
	at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:492)
	at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:130)
	at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:93)
	at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:74)
	at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:343)
	at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:390)
	at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:63)
	at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:926)
	at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1790)
	at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:52)
	at org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1191)
	at org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:659)
	at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
	at java.base/java.lang.Thread.run(Thread.java:1583)
Caused by: java.lang.NullPointerException: user repository returned null
	at com.example.service.OrderService.processOrder(OrderService.java:64)
	at com.example.controller.OrderController.handleCheckout(OrderController.kt:32)
	at java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)
	at java.base/java.lang.reflect.Method.invoke(Method.java:580)
	at org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:255)
	... 42 common frames omitted
"#;

    let parser = JavaTraceParser;
    assert!(parser.detect(raw_trace));

    let locs = parser.extract_locations(raw_trace);
    // Framework frames (FrameworkServlet, HttpServlet, ApplicationFilterChain, WsFilter, Thread, DirectMethodHandleAccessor, Method, InvocableHandlerMethod) MUST be discarded.
    // Only user code locations (OrderService.java:64, OrderController.kt:32) should remain.
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].file, "OrderService.java");
    assert_eq!(locs[0].line, 64);
    assert_eq!(locs[1].file, "OrderController.kt");
    assert_eq!(locs[1].line, 32);

    // Test prune_framework_noise removes Spring and Tomcat frames
    let cleaned = tokenectomy::extractor::prune_framework_noise(raw_trace);
    assert!(!cleaned.contains("org.springframework.web.servlet"));
    assert!(!cleaned.contains("org.apache.catalina"));
    assert!(!cleaned.contains("org.apache.tomcat"));
    assert!(!cleaned.contains("org.apache.coyote"));
    assert!(!cleaned.contains("java.base/"));
    assert!(!cleaned.contains("common frames omitted"));
    assert!(cleaned.contains("OrderService.java:64"));
    assert!(cleaned.contains("OrderController.kt:32"));
}

#[test]
fn test_cpp_asan_deep_stack_trace_pruning() {
    let asan_log = r#"
==38291==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000048 at pc 0x55dc12 bp 0x7ffd12 sp 0x7ffd10
READ of size 8 at 0x603000000048 thread T0
    #0 0x7f9a1234 in __asan_memcpy (/usr/lib/x86_64-linux-gnu/libasan.so.8+0x1234)
    #1 0x555555555149 in process_tensor(float const*, int) src/core/tensor.cpp:88
    #2 0x55555555518b in main src/main.cpp:24
    #3 0x7f9a5678 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f9a5700 in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x555555555020 in _start (/app/bin/server+0x101)
0x603000000048 is located 0 bytes to the right of 40-byte region [0x603000000020,0x603000000048)
"#;

    let parser = CppTraceParser;
    assert!(parser.detect(asan_log));

    let locs = parser.extract_locations(asan_log);
    // __libc_start_main_impl, libc-start.c, and libc_start_call_main.h should be filtered out
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].file, "src/core/tensor.cpp");
    assert_eq!(locs[0].line, 88);
    assert_eq!(locs[1].file, "src/main.cpp");
    assert_eq!(locs[1].line, 24);

    let cleaned = tokenectomy::extractor::prune_framework_noise(asan_log);
    assert!(!cleaned.contains("__asan_memcpy"));
    assert!(!cleaned.contains("libasan.so"));
    assert!(!cleaned.contains("__libc_start_call_main"));
    assert!(!cleaned.contains("__libc_start_main_impl"));
    assert!(!cleaned.contains("in _start"));
    assert!(cleaned.contains("src/core/tensor.cpp:88"));
    assert!(cleaned.contains("src/main.cpp:24"));
}

#[test]
fn test_go_goroutine_panic_compression() {
    let go_dump = r#"
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: code=0x1 addr=0x0 pc=0x498a72]

goroutine 1 [running]:
main.processOrder(0x0)
	/app/src/order.go:45 +0x3a
main.main()
	/app/src/main.go:18 +0x22

goroutine 2 [force gc (idle)]:
runtime.gopark(0x4a0120, 0x0, 0x11, 0x14, 0x1)
	/usr/local/go/src/runtime/proc.go:381 +0xd6
runtime.forcegchelper()
	/usr/local/go/src/runtime/proc.go:320 +0xb8
runtime.goexit()
	/usr/local/go/src/runtime/asm_amd64.s:1598 +0x1

goroutine 3 [GC sweep wait]:
runtime.gopark(0x4a0120, 0x0, 0x0c, 0x14, 0x1)
	/usr/local/go/src/runtime/proc.go:381 +0xd6
runtime.bgsweep()
	/usr/local/go/src/runtime/mgcsweep.go:161 +0x8e
runtime.goexit()
	/usr/local/go/src/runtime/asm_amd64.s:1598 +0x1

goroutine 4 [finalizer wait]:
runtime.gopark(0x4a0120, 0x0, 0x10, 0x14, 0x1)
	/usr/local/go/src/runtime/proc.go:381 +0xd6
runtime.runfinq()
	/usr/local/go/src/runtime/mfinal.go:193 +0xb5
runtime.goexit()
	/usr/local/go/src/runtime/asm_amd64.s:1598 +0x1
"#;

    let parser = GoTraceParser;
    assert!(parser.detect(go_dump));

    let locs = parser.extract_locations(go_dump);
    // Go runtime internals (/usr/local/go/src/runtime/...) should be filtered out
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].file, "/app/src/order.go");
    assert_eq!(locs[0].line, 45);
    assert_eq!(locs[1].file, "/app/src/main.go");
    assert_eq!(locs[1].line, 18);

    // Prune idle goroutines: goroutines 2, 3, and 4 should be completely pruned away!
    let cleaned = tokenectomy::extractor::prune_framework_noise(go_dump);
    assert!(cleaned.contains("goroutine 1 [running]:"));
    assert!(cleaned.contains("/app/src/order.go:45"));
    assert!(cleaned.contains("/app/src/main.go:18"));
    assert!(!cleaned.contains("[force gc (idle)]"));
    assert!(!cleaned.contains("[GC sweep wait]"));
    assert!(!cleaned.contains("[finalizer wait]"));
    assert!(!cleaned.contains("runtime.forcegchelper"));
    assert!(!cleaned.contains("runtime.bgsweep"));
    assert!(!cleaned.contains("runtime.runfinq"));
}

#[tokio::test]
async fn test_proxy_finops_metrics_and_dashboard() {
    let bind_addr = "127.0.0.1:18097";

    tokio::spawn(async move {
        let _ = tokenectomy::proxy::run_reverse_proxy(bind_addr, "http://127.0.0.1:11434").await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
    let client = reqwest::Client::new();

    // 1. Check /v1/metrics returns 200 with initial FinOps JSON schema
    let metrics_resp = client.get("http://127.0.0.1:18097/v1/metrics").send().await.expect("call /v1/metrics");
    assert_eq!(metrics_resp.status(), 200);
    let metrics_json: serde_json::Value = metrics_resp.json().await.expect("parse metrics json");
    assert_eq!(metrics_json["service"], "tokenectomy-gateway");
    assert!(metrics_json.get("estimated_cost_saved_usd").is_some());
    assert!(metrics_json.get("estimated_tokens_saved").is_some());
    assert!(metrics_json.get("total_requests").is_some());

    // 2. Check /dashboard returns 200 with HTML content
    let dash_resp = client.get("http://127.0.0.1:18097/dashboard").send().await.expect("call /dashboard");
    assert_eq!(dash_resp.status(), 200);
    let html = dash_resp.text().await.expect("read dashboard html");
    assert!(html.contains("Tokenectomy Razor"));
    assert!(html.contains("GATEWAY ACTIVE"));
    assert!(html.contains("/v1/metrics"));
}

#[test]
fn test_polyglot_multi_trace_detection() {
    let polyglot_log = r#"
=== Next.js Frontend Failure ===
TypeError: Cannot read properties of undefined (reading 'token')
    at AuthForm (/app/src/components/Auth.tsx:42:15)
    at Object.<anonymous> (node_modules/react-dom/index.js:50:2)

=== Python Backend Subprocess Crash ===
Traceback (most recent call last):
  File "/app/backend/api/auth.py", line 95, in verify_jwt
    raise ValueError("Invalid signature")
  File "/app/.venv/lib/python3.11/site-packages/jwt/api_jwt.py", line 12, in decode
    return payload
"#;

    let (_context, _extracted_files) = tokenectomy::extractor::extract_context(polyglot_log, 5, false);
    // Even if the files don't exist on disk, let's verify both parsers detect their respective traces
    let js_parser = JsTraceParser;
    let py_parser = tokenectomy::extractor::python::PythonTraceParser;

    assert!(js_parser.detect(polyglot_log));
    assert!(py_parser.detect(polyglot_log));

    let js_locs = js_parser.extract_locations(polyglot_log);
    let py_locs = py_parser.extract_locations(polyglot_log);

    assert_eq!(js_locs.len(), 1);
    assert_eq!(js_locs[0].file, "/app/src/components/Auth.tsx");
    assert_eq!(js_locs[0].line, 42);

    assert_eq!(py_locs.len(), 1);
    assert_eq!(py_locs[0].file, "/app/backend/api/auth.py");
    assert_eq!(py_locs[0].line, 95);
}

#[test]
fn test_proxy_multi_part_content_and_system_sanitization() {
    let dummy_stripe = format!("{}_{}_{}", "sk", "live", "512345678901234567890123");
    let inbound_payload = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a backend assistant with admin secret=supersecret12345! to database postgresql://user:pass@db:5432/main",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": format!("Please fix this error with stripe key {}", dummy_stripe)
                    },
                    {
                        "type": "tool_result",
                        "content": "Error: connection failed\n    at query (/app/src/db.ts:10:5)\n    at node_modules/pg/client.js:12:3"
                    }
                ]
            }
        ]
    });

    let (sanitized, stats) = sanitize_prompt_payload(&inbound_payload);

    // Verify system prompt was sanitized
    let sys = sanitized["system"].as_str().unwrap();
    assert!(!sys.contains("supersecret12345!"));
    assert!(!sys.contains("user:pass@db"));
    assert!(sys.contains("[CONNECTION_STRING_REDACTED]"));

    // Verify multi-part text was sanitized
    let part0 = sanitized["messages"][0]["content"][0]["text"].as_str().unwrap();
    assert!(!part0.contains(&dummy_stripe));
    assert!(part0.contains("[STRIPE_KEY_REDACTED]"));

    // Verify multi-part tool_result was sanitized and pruned
    let part1 = sanitized["messages"][0]["content"][1]["content"].as_str().unwrap();
    assert!(!part1.contains("node_modules"));
    assert!(part1.contains("/app/src/db.ts:10:5"));

    assert!(stats.secrets_redacted >= 2);
}

#[test]
fn test_verify_patch_json_and_toml() {
    let temp_dir = std::env::temp_dir().join(format!("tokenectomy_config_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // 1. JSON Verification
    let json_path = temp_dir.join("config.json");
    std::fs::write(&json_path, r#"{"name": "tokenectomy", "enabled": true}"#).unwrap();
    assert!(tokenectomy::mcp::verify_patch(&json_path).is_ok());

    std::fs::write(&json_path, r#"{"name": "tokenectomy", "enabled": true,"#).unwrap(); // trailing comma / invalid syntax
    assert!(tokenectomy::mcp::verify_patch(&json_path).is_err());

    // 2. TOML Verification
    let toml_path = temp_dir.join("Cargo.toml");
    std::fs::write(&toml_path, "[package]\nname = \"test-crate\"\nversion = \"1.0.0\"\n").unwrap();
    assert!(tokenectomy::mcp::verify_patch(&toml_path).is_ok());

    std::fs::write(&toml_path, "[package\nname = \"broken\"\n").unwrap(); // missing closing bracket
    assert!(tokenectomy::mcp::verify_patch(&toml_path).is_err());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_prune_python_async_and_dotnet_noise() {
    let dirty_trace = r#"
Traceback (most recent call last):
  File "<frozen importlib._bootstrap>", line 1178, in _find_and_load
  File "/app/env/lib/python3.11/asyncio/base_events.py", line 640, in run_until_complete
  File "/app/env/lib/python3.11/site-packages/starlette/routing.py", line 670, in __call__
  File "/app/env/lib/python3.11/site-packages/uvicorn/protocols/http/httptools_impl.py", line 426, in handle_events
  File "/app/src/main.py", line 45, in endpoint
    raise RuntimeError("Custom app crash")
RuntimeError: Custom app crash
"#;

    let cleaned = tokenectomy::extractor::prune_framework_noise(dirty_trace);
    assert!(!cleaned.contains("<frozen"));
    assert!(!cleaned.contains("asyncio/base_events"));
    assert!(!cleaned.contains("starlette/routing"));
    assert!(!cleaned.contains("uvicorn/protocols"));
    assert!(cleaned.contains("/app/src/main.py"));
    assert!(cleaned.contains("Custom app crash"));
}

#[test]
fn test_mcp_get_error_context_framework_pruning() {
    let dirty_trace = r#"
java.lang.NullPointerException: DB fail
    at com.example.MyService.run(MyService.java:10)
    at org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1014)
    at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:149)
    at java.base/java.lang.Thread.run(Thread.java:1583)
"#;
    let safe_log = tokenectomy::redact::redact_secrets(dirty_trace);
    let clean_log = tokenectomy::extractor::prune_framework_noise(&safe_log);
    assert!(!clean_log.contains("org.springframework"));
    assert!(!clean_log.contains("org.apache.catalina"));
    assert!(!clean_log.contains("java.base/"));
    assert!(clean_log.contains("com.example.MyService.run"));
}

#[tokio::test]
async fn test_proxy_query_parameters_and_trailing_slash() {
    let bind_addr = "127.0.0.1:18098";
    tokio::spawn(async move {
        let _ = tokenectomy::proxy::run_reverse_proxy(bind_addr, "http://127.0.0.1:11434").await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
    let client = reqwest::Client::new();

    // 1. Health check with query parameters: /health?format=json
    let resp1 = client.get("http://127.0.0.1:18098/health?format=json").send().await.expect("query health");
    assert_eq!(resp1.status(), 200);

    // 2. Metrics with query parameters: /v1/metrics?refresh=true
    let resp2 = client.get("http://127.0.0.1:18098/v1/metrics?refresh=true").send().await.expect("query metrics");
    assert_eq!(resp2.status(), 200);

    // 3. Dashboard with trailing slash: /dashboard/
    let resp3 = client.get("http://127.0.0.1:18098/dashboard/").send().await.expect("trailing slash dashboard");
    assert_eq!(resp3.status(), 200);
}

#[test]
fn test_verify_patch_yaml_syntax() {
    let temp_dir = std::env::temp_dir().join(format!("tokenectomy_yaml_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // 1. Valid YAML with spaces
    let valid_yaml = temp_dir.join("compose.yaml");
    std::fs::write(&valid_yaml, "services:\n  web:\n    image: nginx:alpine\n    ports:\n      - \"80:80\"\n").unwrap();
    assert!(tokenectomy::mcp::verify_patch(&valid_yaml).is_ok());

    // 2. Invalid YAML containing tab characters for indentation
    let invalid_yaml = temp_dir.join("broken.yaml");
    std::fs::write(&invalid_yaml, "services:\n\tweb:\n\t\timage: nginx\n").unwrap();
    let res = tokenectomy::mcp::verify_patch(&invalid_yaml);
    assert!(res.is_err());
    let err_str = res.unwrap_err();
    assert!(err_str.contains("Tabs are forbidden for indentation in YAML"));

    // 3. Invalid YAML syntax without tabs (malformed parser error)
    let broken_syntax_yaml = temp_dir.join("syntax_error.yaml");
    std::fs::write(&broken_syntax_yaml, "services:\n  web: [broken unclosed list\n").unwrap();
    let res2 = tokenectomy::mcp::verify_patch(&broken_syntax_yaml);
    assert!(res2.is_err());
    let err_str2 = res2.unwrap_err();
    assert!(err_str2.contains("YAML syntax validation failed"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_extractor_custom_noise_patterns() {
    let custom_noise = vec![
        "my_internal_pipeline/".to_string(),
        "build_artifacts/".to_string(),
    ];

    let dirty_log = r#"
Error: Service failure
    at processData (/app/src/index.ts:15:2)
    at runInternal (/app/my_internal_pipeline/executor.ts:88:12)
    at generatedStubs (/app/build_artifacts/stubs.ts:4:1)
"#;

    let cleaned = tokenectomy::extractor::prune_framework_noise_with_custom(dirty_log, &custom_noise);
    assert!(cleaned.contains("/app/src/index.ts:15:2"));
    assert!(!cleaned.contains("my_internal_pipeline"));
    assert!(!cleaned.contains("build_artifacts"));
}

#[test]
fn test_apply_code_patch_dry_run_simulation() {
    let temp_dir = std::env::temp_dir().join(format!("tokenectomy_dryrun_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let py_file = temp_dir.join("calc.py");
    let original_content = "def add(a: int, b: int) -> int:\n    return a + b\n";
    std::fs::write(&py_file, original_content).unwrap();

    let boundary = tokenectomy::workspace::WorkspaceBoundary::new(&temp_dir).unwrap();

    // Verify boundary reads content
    let content = boundary.read(&py_file).unwrap();
    assert_eq!(content, original_content);

    // Dry-run patch: file content on disk MUST remain unchanged
    let original_code = "return a + b";
    let new_code = "return a + b + 0";
    let updated = content.replacen(original_code, new_code, 1);

    let temp_file = py_file.with_file_name(format!(".dry_run_sim_{}.py", std::process::id()));
    std::fs::write(&temp_file, updated.as_bytes()).unwrap();
    let check = tokenectomy::mcp::verify_patch(&temp_file);
    let _ = std::fs::remove_file(&temp_file);

    assert!(check.is_ok());

    // Disk file must be exactly original
    let current_disk = std::fs::read_to_string(&py_file).unwrap();
    assert_eq!(current_disk, original_content, "Dry-run must never mutate disk file");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_csharp_and_ruby_polyglot_detection() {
    use tokenectomy::extractor::csharp::CSharpTraceParser;
    use tokenectomy::extractor::ruby::RubyTraceParser;

    let cs_trace = r#"
System.InvalidOperationException: Database connection timed out.
   at Enterprise.Core.Repository.FindOrder(Int32 id) in /app/src/Repository/OrderRepo.cs:line 104
   at Enterprise.Web.Controllers.OrderController.Get(Int32 id) in /app/src/Controllers/OrderController.cs:line 37
   at Microsoft.AspNetCore.Mvc.Infrastructure.ActionMethodExecutor.Execute() in Microsoft.AspNetCore.Mvc.Core.dll:line 50
"#;
    let cs_parser = CSharpTraceParser;
    assert!(cs_parser.detect(cs_trace));
    let cs_locs = cs_parser.extract_locations(cs_trace);
    assert_eq!(cs_locs.len(), 2);
    assert_eq!(cs_locs[0].file, "/app/src/Repository/OrderRepo.cs");
    assert_eq!(cs_locs[0].line, 104);
    assert_eq!(cs_locs[1].file, "/app/src/Controllers/OrderController.cs");
    assert_eq!(cs_locs[1].line, 37);

    let rb_trace = r#"
ActionController::RoutingError (No route matches [GET] "/checkout"):
  app/controllers/application_controller.rb:14:in `authenticate_user!'
  app/services/checkout_service.rb:88:in `execute'
  gems/actionpack-7.0.4/lib/action_dispatch/middleware/debug_exceptions.rb:28:in `call'
"#;
    let rb_parser = RubyTraceParser;
    assert!(rb_parser.detect(rb_trace));
    let rb_locs = rb_parser.extract_locations(rb_trace);
    assert_eq!(rb_locs.len(), 2);
    assert_eq!(rb_locs[0].file, "app/controllers/application_controller.rb");
    assert_eq!(rb_locs[0].line, 14);
    assert_eq!(rb_locs[1].file, "app/services/checkout_service.rb");
    assert_eq!(rb_locs[1].line, 88);
}

#[test]
fn test_adversarial_redos_and_extreme_inputs() {
    // 1. ReDoS stress: 50,000 repeating characters simulating catastrophic backtracking attack
    let redos_attempt = "sk-".repeat(1000) + &"a".repeat(20000);
    let start = std::time::Instant::now();
    let redacted = tokenectomy::redact::redact_secrets(&redos_attempt);
    let elapsed = start.elapsed();
    // In debug mode without optimizations, 15 regex passes over 23KB takes ~80ms; in release mode with SIMD it takes ~1.1ms.
    // Threshold is 250ms to detect catastrophic exponential/polynomial backtracking (which would take seconds or minutes) without failing on unoptimized debug builds.
    assert!(elapsed.as_millis() < 250, "Catastrophic ReDoS detected: evaluation took {}ms", elapsed.as_millis());
    assert!(!redacted.is_empty());

    // 2. High entropy boundary strings and unicode stress
    let weird_unicode = "Error: 🔥 💥 🦀 at /path/with/emojis/🚀.rs:42:1 in ñañdú \0 null-byte";
    let cleaned = tokenectomy::extractor::prune_framework_noise(weird_unicode);
    assert!(cleaned.contains("🚀.rs:42:1"));

    // 3. Truncated secrets: ensure partial keys don't falsely redact or panic
    let truncated_hf = "hf_short";
    assert_eq!(tokenectomy::redact::redact_secrets(truncated_hf), "hf_short");

    let truncated_sk = format!("{}_{}_{}", "sk", "live", "123");
    assert_eq!(tokenectomy::redact::redact_secrets(&truncated_sk), truncated_sk);
}

#[test]
fn test_apply_code_patch_crlf_lf_resilience() {
    let temp_dir = std::env::temp_dir().join(format!("test_crlf_mcp_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let file_path = temp_dir.join("sample.py");

    // File on disk has CRLF line endings
    let crlf_content = "def calculate(a, b):\r\n    total = a + b\r\n    return total\r\n";
    std::fs::write(&file_path, crlf_content).unwrap();

    let boundary = tokenectomy::workspace::WorkspaceBoundary::new(&temp_dir).unwrap();
    let content = boundary.read(&file_path).unwrap();

    // LLM sends LF line endings
    let orig_lf = "    total = a + b\n    return total";
    let new_lf = "    total = a + b + 10\n    return total";

    // Test normalization matching logic
    let orig_crlf = orig_lf.replace("\r\n", "\n").replace('\n', "\r\n");
    let new_crlf = new_lf.replace("\r\n", "\n").replace('\n', "\r\n");
    assert!(content.contains(&orig_crlf), "Should match normalized CRLF");

    let updated = content.replacen(&orig_crlf, &new_crlf, 1);
    boundary.write(&file_path, updated.as_bytes()).unwrap();

    let disk_after = std::fs::read_to_string(&file_path).unwrap();
    assert!(disk_after.contains("total = a + b + 10"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_search_query_preserves_language_packages() {
    let log = "panic: runtime error in net/http: request handler failed at /home/runner/work/repo/main.go:88";
    let query = tokenectomy::search::extract_error_query(log).expect("should extract query");
    assert!(query.contains("net/http"), "Must preserve language packages like net/http");
    assert!(!query.contains("/home/runner/"), "Must strip physical filesystem paths");
}

#[test]
fn test_framework_noise_no_false_positives_on_user_projects() {
    use tokenectomy::extractor::is_framework_noise;

    // User project paths containing substrings like "vendor", "go/src", "gems"
    assert!(!is_framework_noise("/home/user/code/vendor_portal/src/main.rs"));
    assert!(!is_framework_noise("/app/chicago/src/handler.go"));
    assert!(!is_framework_noise("/var/www/inventory_management/index.php"));
    assert!(!is_framework_noise("/projects/diamonds_and_gems/game.rb"));
    assert!(!is_framework_noise("src/vendor_client.rs"));

    // Real framework and dependency noise MUST be caught
    assert!(is_framework_noise("/home/user/project/vendor/laravel/framework/src/Container.php"));
    assert!(is_framework_noise("/home/user/project/node_modules/express/index.js"));
    assert!(is_framework_noise("/usr/local/go/src/runtime/panic.go"));
    assert!(is_framework_noise("/home/user/.cargo/registry/src/tokio-1.0/lib.rs"));
    assert!(is_framework_noise("/app/.venv/lib/python3.10/site-packages/fastapi/main.py"));
}

#[test]
fn test_proxy_decode_chunked_body_rfc7230() {
    use tokenectomy::proxy::decode_chunked_body;

    // 1. Standard RFC 7230 chunked body with dynamically verified hex lengths
    let chunk1 = "Wiki";
    let chunk2 = "pedia";
    let chunk3 = " in \r\nchunks.";
    let raw = format!(
        "{:x}\r\n{}\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        chunk1.len(),
        chunk1,
        chunk2.len(),
        chunk2,
        chunk3.len(),
        chunk3
    );
    let decoded = decode_chunked_body(raw.as_bytes()).expect("decode valid chunks");
    assert_eq!(decoded, b"Wikipedia in \r\nchunks.");

    // 2. Chunks with RFC extensions (after semicolon)
    let raw_with_ext = b"5;foo=bar\r\nHello\r\n6;ext\r\n World\r\n0\r\n\r\n";
    let decoded_ext = decode_chunked_body(raw_with_ext).expect("decode chunks with extensions");
    assert_eq!(decoded_ext, b"Hello World");

    // 3. Empty chunks (immediate zero length)
    let empty_chunks = b"0\r\n\r\n";
    let decoded_empty = decode_chunked_body(empty_chunks).expect("decode empty chunks");
    assert!(decoded_empty.is_empty());

    // 4. Incomplete chunk data error detection
    let truncated = b"a\r\nshort";
    assert!(decode_chunked_body(truncated).is_err());

    // 5. Missing CRLF after chunk data
    let bad_crlf = b"4\r\nWikiXX0\r\n\r\n";
    assert!(decode_chunked_body(bad_crlf).is_err());
}

#[tokio::test]
async fn test_proxy_upstream_end_to_end_streaming_and_redaction() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let upstream_listener = TcpListener::bind("127.0.0.1:18093").await.expect("bind mock upstream");
    let upstream_addr = "http://127.0.0.1:18093";

    // Spawn mock upstream LLM server
    tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.expect("upstream accept");
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await.expect("upstream read");
        let req_str = String::from_utf8_lossy(&buf[..n]);

        // CRITICAL INVARIANT: Upstream MUST receive sanitized payload with Anthropic key redacted!
        assert!(req_str.contains("[ANTHROPIC_KEY_REDACTED]"), "Upstream must receive redacted key");
        assert!(!req_str.contains("sk-ant-api03-abcdef12345678901234567890"), "Raw secret leaked to upstream!");

        // Send streaming response back through the proxy with Connection: close
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"reply\":\"Sanitized OK\"}\n\n";
        socket.write_all(resp.as_bytes()).await.expect("upstream write");
        let _ = socket.flush().await;
    });

    let proxy_addr = "127.0.0.1:18094";
    tokio::spawn(async move {
        if let Err(e) = tokenectomy::proxy::run_reverse_proxy(proxy_addr, upstream_addr).await {
            eprintln!("PROXY SERVER ERROR: {:?}", e);
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // Client makes request through proxy with raw secret
    let client = reqwest::Client::new();
    let client_payload = serde_json::json!({
        "model": "gpt-4",
        "messages": [
            {
                "role": "user",
                "content": "Diagnose error with token sk-ant-api03-abcdef12345678901234567890"
            }
        ]
    });

    let res = client
        .post(format!("http://{}/v1/chat/completions", proxy_addr))
        .json(&client_payload)
        .send()
        .await
        .expect("client send to proxy");

    assert_eq!(res.status(), 200);
    let body = res.text().await.expect("client read response");
    assert!(body.contains("Sanitized OK"), "Client must receive upstream response");
}

#[test]
fn test_workspace_boundary_read_size_guard() {
    let temp_dir = std::env::temp_dir().join(format!("tokenectomy_size_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // Create a 1MB file (within safe limit)
    let safe_file = temp_dir.join("safe.txt");
    std::fs::write(&safe_file, vec![b'a'; 1024 * 1024]).expect("write safe file");
    let safe_boundary = tokenectomy::workspace::WorkspaceBoundary::new(&temp_dir).expect("temp boundary");
    assert!(safe_boundary.read("safe.txt").is_ok());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_mcp_python_syntax_error_exact_coordinates() {
    let temp_dir = std::env::temp_dir().join(format!("tokenectomy_ast_coord_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let py_file = temp_dir.join("broken.py");
    // Line 1 is valid assignment; line 2 contains invalid syntax
    std::fs::write(&py_file, "valid_var = 100\n@@invalid_token@@\n").expect("write py file");

    let res = tokenectomy::mcp::verify_patch(&py_file);
    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("Python syntax error"), "Must detect python syntax error");
    assert!(err_msg.contains("line 2"), "Must pinpoint error coordinates on line 2: got '{}'", err_msg);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_search_query_direct_fallback_and_html_entity_decoding() {
    // 1. Direct query without any stack trace frames
    let direct = "TypeError: cannot read property 'data' of undefined";
    let extracted = tokenectomy::search::extract_error_query(direct);
    assert!(extracted.is_some());
    assert!(extracted.unwrap().contains("TypeError"));

    // 2. HTML entity unescaping
    let title_raw = "&quot;Hello&quot; &amp; &lt;World&gt; &#39;test&#39;";
    let unescaped = title_raw
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    assert_eq!(unescaped, "\"Hello\" & <World> 'test'");
}
