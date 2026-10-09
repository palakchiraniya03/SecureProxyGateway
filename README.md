# SecureProxyGateway

A high-reliability, security-hardened HTTP/1.1 and HTTPS CONNECT forward proxy gateway written in modern C++17 using POSIX sockets and native threading.

---

## Overview

**SecureProxyGateway** acts as an intermediary network gateway between client applications (such as browsers, command-line tools, and automated services) and external network destinations. Designed to demonstrate robust systems programming and defensive network security, the gateway listens on `127.0.0.1:8080`, enforces mandatory HTTP Basic proxy authentication (RFC 7617), performs comprehensive Server-Side Request Forgery (SSRF) filtering against internal and reserved IP ranges, and supports two distinct forwarding modes:

1. **Plain HTTP Forward Proxying**: Parses, sanitizes, and rebuilds canonical HTTP/1.1 requests, strips hop-by-hop headers to prevent HTTP request smuggling, enforces request body size limits and deadlines, and streams server responses chunk-by-chunk back to the client.
2. **HTTPS CONNECT Tunneling**: Establishes end-to-end, non-blocking bidirectional TCP byte tunnels via the HTTP `CONNECT` method (RFC 7231). TLS traffic passes through the tunnel transparently without decryption or inspection, preserving client-to-destination cryptographic privacy while enforcing strict port restrictions, concurrency limits, and TCP half-close handling.

### Technical Highlights
- **Low-Level POSIX Networking**: Direct implementation using Linux socket APIs (`socket`, `bind`, `listen`, `accept`, `poll`, `recv`, `send`, `shutdown`, `fcntl`) without external networking libraries.
- **Fixed-Size Worker Thread Pool**: Handles incoming client connections concurrently using a pre-allocated pool of 32 worker threads, condition variables, and thread-safe task queues.
- **Defense-in-Depth Security**: Validates all resolved IPv4 and IPv6 addresses against private (RFC 1918), loopback, link-local, carrier-grade NAT (RFC 6598), 6to4, Teredo, and multicast ranges before establishing outbound connections.
- **Timing-Attack Resistance**: Uses constant-time string comparison for credential verification during proxy authentication.
- **Poll-Driven Bidirectional Relay**: Employs non-blocking sockets and `poll()` with asymmetric TCP half-close handling (`SHUT_WR` / FIN propagation) and backpressure buffer management.
- **Zero-Warning Clean Build & CI**: Compiles cleanly with `-Wall -Wextra -Wpedantic` on C++17, verified by a 355-test automated test suite and GitHub Actions CI.

---

## Architecture

The gateway operates on a connection-per-task model dispatched to a fixed-size worker thread pool. Incoming client connections follow a strict processing pipeline: socket acceptance, header ingestion within bounded buffer limits, proxy authentication, request routing based on HTTP method, SSRF IP validation, outbound connection establishment, and data forwarding.

```mermaid
flowchart TD
    subgraph Ingress ["1. Ingress & Authentication"]
        Client["Client (curl / browser)"] -->|TCP Connection| Listener["TCP Listener (127.0.0.1:8080)"]
        Listener -->|Accept socket| Pool["Fixed Worker ThreadPool (32 threads)"]
        Pool --> ReadReq["Read Headers (8 KB cap, 10s deadline)"]
        ReadReq --> ParseReq["HTTP Parser (Validate method, target, headers)"]
        ParseReq --> AuthCheck{"Proxy-Authorization?<br/>(Constant-Time Basic Auth)"}
        AuthCheck -->|Unauthorized / Missing| Resp407["407 Proxy Authentication Required"]
    end

    subgraph Dispatch ["2. Routing & Pre-Flight Validation"]
        AuthCheck -->|Authorized| RouteCheck{"Request Method"}
        RouteCheck -->|GET, POST, etc.| HTTPPreflight["Plain HTTP Forwarding<br/>(Body cap <= 10 MB, reject https:// target)"]
        RouteCheck -->|CONNECT| ConnPreflight["HTTPS CONNECT Tunneling<br/>(Allowed ports: 443, 8443; Concurrency <= 28)"]
    end

    subgraph Security ["3. Outbound SSRF Protection"]
        HTTPPreflight --> ResolveHTTP["Resolve Hostname (getaddrinfo)"]
        ConnPreflight --> ResolveConn["Resolve Hostname (getaddrinfo)"]
        ResolveHTTP --> SSRF_HTTP{"Inspect Resolved IPs<br/>(IPv4 & IPv6)"}
        ResolveConn --> SSRF_Conn{"Inspect Resolved IPs<br/>(IPv4 & IPv6)"}
        SSRF_HTTP -->|Private / Loopback / Blocked| BlockHTTP["403 Forbidden"]
        SSRF_Conn -->|Private / Loopback / Blocked| BlockConn["403 Forbidden"]
    end

    subgraph OutboundHTTP ["4A. Plain HTTP Forwarding"]
        SSRF_HTTP -->|Safe Outbound IP| ConnectHTTP["Connect to Destination (10s budget)"]
        ConnectHTTP --> Rebuild["Rebuild Canonical Origin-Form Request<br/>(Strip hop-by-hop headers & proxy auth)"]
        Rebuild --> SendHTTP["Forward Request & Stream Response"]
        SendHTTP --> CompleteHTTP["Close Connection (60s total deadline)"]
    end

    subgraph OutboundCONNECT ["4B. HTTPS CONNECT Tunneling"]
        SSRF_Conn -->|Safe Outbound IP| ConnectConn["Connect to Destination (10s budget)"]
        ConnectConn --> Handshake200["Send '200 Connection Established'"]
        Handshake200 --> Relay["Bidirectional Non-Blocking TCP Relay<br/>(poll-driven, 16 KB buffers)"]
        Relay --> Passthrough["Transparent TLS Passthrough<br/>(End-to-end encrypted; no TLS decryption)"]
        Passthrough --> HalfClose["TCP Half-Close (FIN propagation)<br/>& Backpressure Buffer Drainage"]
        HalfClose --> ReleaseConn["Release Concurrency Slot & Close"]
    end
```

---

## Key Features

### Multithreaded POSIX TCP Server (`src/main.cpp`, `src/thread_pool.cpp`)
- Listens on `127.0.0.1:8080` with `SO_REUSEADDR` enabled for immediate socket rebinding upon restart.
- Manages concurrency through a pre-forked `ThreadPool` containing 32 persistent worker threads.
- Worker threads pull tasks from a thread-safe task queue synchronized via `std::mutex` and `std::condition_variable`.
- Configures individual socket timeouts (`SO_RCVTIMEO` and `SO_SNDTIMEO`) alongside explicit `poll()` deadlines to mitigate slow-client and stalled-connection starvation.
- Implements clean signal handling for `SIGINT` and `SIGTERM` with `SIGPIPE` safely ignored.

### Custom HTTP/1.1 Request Parser (`src/http_parser.cpp`)
- Zero-dependency parser implementing RFC 7230 and RFC 7231 specifications.
- Supports origin-form (`/path`), absolute URI (`http://host/path`), and CONNECT authority-form (`host:port`).
- Enforces strict CRLF (`\r\n`) line terminations, rejecting bare CR or LF characters in request lines and headers.
- Rejects malformed header names, leading/trailing whitespace around delimiters, invalid HTTP versions, control characters, and duplicate `Host` headers.
- Normalizes destination hostnames to lowercase and automatically sanitizes sensitive query strings in server log outputs.
- Enforces a strict 8 KB header block limit (`MAX_HEADER_BLOCK_SIZE`) to defend against memory exhaustion and header flooding.

### Proxy Authentication (`src/authenticator.cpp`)
- Implements RFC 7617 HTTP Basic authentication via the `Proxy-Authorization` header.
- Responds with `HTTP/1.1 407 Proxy Authentication Required` and a standard `Proxy-Authenticate: Basic realm="SecureProxyGateway"` challenge when credentials are missing or invalid.
- Includes a built-in Base64 decoder with padding checks and character set validation.
- Employs constant-time string comparison (`constant_time_equals`) to prevent timing side-channel attacks on usernames and passwords.

### Plain HTTP Forwarding (`src/http_forwarder.cpp`)
- Rebuilds client requests into canonical origin-form requests with normalized `Host` headers.
- Strips hop-by-hop headers (`Connection`, `Proxy-Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Expect`, `Proxy-Authorization`) and appends `Connection: close` to prevent HTTP request smuggling.
- Enforces a 10 MB maximum request body limit (`MAX_BODY_BYTES`), returning `HTTP/1.1 413 Payload Too Large` if exceeded.
- Rejects plain HTTP forwarding for HTTPS targets (`https://...`), returning `HTTP/1.1 501 Not Implemented` with instructions to use CONNECT tunneling.
- Employs a single 60-second total deadline across body ingestion, outbound connection, request dispatch, and response streaming.
- Streams destination responses back to the client in 8 KB chunks without loading full responses into proxy memory.

### HTTPS CONNECT Tunneling (`src/http_forwarder.cpp`)
- Implements RFC 7231 `CONNECT` authority tunneling for transparent TLS passthrough without decrypting or altering payloads.
- Restricts destination ports to standard HTTPS ports (`443` and `8443`), rejecting other destination ports with `HTTP/1.1 403 Forbidden`.
- Restricts active tunnels to a maximum of 28 concurrent sessions using atomic compare-and-swap operations, returning `HTTP/1.1 503 Service Unavailable` when saturated.
- Sends `HTTP/1.1 200 Connection Established` to the client upon successful outbound connection establishment.
- Executes a non-blocking bidirectional relay (`relay_tunnel`) utilizing `poll()` and independent 16 KB transfer buffers.
- Correctly propagates TCP half-close: forwards FIN via `shutdown(SHUT_WR)` when a peer closes its write end while continuing to drain data in the opposite direction under TCP backpressure.
- Enforces an idle timeout (60 seconds) and an absolute session lifetime cap (15 minutes).

---

## Security Design

### Server-Side Request Forgery (SSRF) Protection
Before any outbound connection is established (in either plain forwarding or CONNECT tunneling mode), all resolved IP addresses from `getaddrinfo()` are evaluated by `HttpForwarder::is_ssrf_safe`. Outbound connections are blocked if any resolved IP falls into restricted or internal address spaces:

| Network Category | Blocked Range | Specification |
|---|---|---|
| Unspecified / Current Network | `0.0.0.0/8` | RFC 1122 |
| IPv4 Loopback | `127.0.0.0/8` | RFC 1122 |
| IPv4 Private Networks | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 |
| Carrier-Grade NAT (CGNAT) | `100.64.0.0/10` | RFC 6598 |
| Link-Local | `169.254.0.0/16` | RFC 3927 |
| IETF Protocol Assignments | `192.0.0.0/24` | RFC 6890 |
| Benchmarking | `198.18.0.0/15` | RFC 2544 |
| Multicast & Reserved (Class E) | `224.0.0.0/4`, `240.0.0.0/4` | RFC 1112, RFC 5771 |
| IPv6 Unspecified & Loopback | `::`, `::1` | RFC 4291 |
| IPv6 Link-Local & Site-Local | `fe80::/10`, `fec0::/10` | RFC 4291, RFC 3879 |
| Unique Local Addresses (ULA) | `fc00::/7` | RFC 4193 |
| IPv4/IPv6 Translation | `64:ff9b::/96` | RFC 6052 |
| 6to4 & Teredo Translation | `2002::/16`, `2001::/32` | RFC 3056, RFC 4380 |
| IPv6 Multicast | `ff00::/8` | RFC 4291 |
| IPv4-Mapped & Compatible IPv6 | `::ffff:0:0/96`, `::/96` | Unpacked and checked against IPv4 rules |

Even when loopback is explicitly enabled for unit tests, connections targeting the gateway's own listening port (`127.0.0.1:8080`) are strictly prohibited to prevent recursive proxy loops.

### Timing Attack Mitigation
The authentication module evaluates credentials using byte-level XOR accumulation:
```cpp
bool constant_time_equals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}
```
This ensures consistent comparison duration regardless of matching prefix characters, mitigating side-channel timing analysis.

### Request Smuggling & Header Sanitization
- Enforces strict CRLF header separators and prohibits conflicting framing headers (e.g., rejecting requests containing `Transfer-Encoding` or duplicate `Content-Length`/`Host` headers).
- Sanitizes request headers prior to forwarding by stripping all hop-by-hop headers (`Connection`, `Proxy-Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Expect`, `Proxy-Authorization`).

### Resource Exhaustion Defenses
- **Header Block Cap**: Max 8 KB per request.
- **Header Read Deadline**: 10-second timeout to mitigate Slowloris header-drip attacks.
- **Body Size Limit**: Max 10 MB per plain HTTP request.
- **Forwarding Deadline**: 60-second total deadline for plain HTTP request dispatch and response streaming.
- **Tunnel Lifetime Caps**: 60-second idle timeout and 15-minute maximum session duration for CONNECT tunnels.
- **Tunnel Concurrency Cap**: Max 28 concurrent CONNECT tunnels across the 32-thread pool.

### Security Notice

> [!CAUTION]
> The configured `Proxy-Authorization` credentials (`palak:secureproxy`) are **demo-only**.
> These credentials must **not** be reused as a real password or in any production environment.
> This authentication mechanism is intended strictly for local and student demonstration purposes.

---

## Build and Run

### Prerequisites
- Linux OS
- C++17 compliant compiler (`g++` 9+ or `clang++` 10+)
- CMake 3.15 or newer
- Make or Ninja build system

### Building the Gateway
```bash
# Configure the build directory in Release mode
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Compile the gateway executable and all test suites
cmake --build build --parallel 2
```

### Running the Gateway
```bash
./build/secure_proxy_gateway
```
The server will start listening on `127.0.0.1:8080`:
```text
Secure Proxy Gateway starting...
Thread pool started with 32 worker threads.
Server listening on 127.0.0.1:8080...
```

### Example Usage with `curl`

#### 1. Unauthenticated Request (Expect `407 Proxy Authentication Required`)
```bash
curl -i -x http://127.0.0.1:8080 http://example.com/
```

#### 2. Authenticated Plain HTTP Forwarding
```bash
curl -i -x http://palak:secureproxy@127.0.0.1:8080 http://example.com/
```

#### 3. Authenticated HTTPS CONNECT Tunneling
```bash
curl -i -x http://palak:secureproxy@127.0.0.1:8080 https://example.com/
```

#### 4. SSRF Block Verification (Expect `403 Forbidden`)
```bash
curl -i -x http://palak:secureproxy@127.0.0.1:8080 http://127.0.0.1:22/
```

---

## Testing

The project maintains comprehensive test coverage across 5 dedicated test suites comprising 355 test cases.

### Running Tests via CTest
```bash
ctest --test-dir build --output-on-failure
```

### Test Suite Breakdown

| Test Suite Target | Executable | Test Count | Scope & Coverage |
|---|---|:---:|---|
| `HttpParserTest` | `test_http_parser` | 130 | Origin, absolute, and authority request formats; header parsing; strict CRLF validation; path sanitization; 8 KB boundary handling; malformed request rejections. |
| `ThreadPoolTest` | `test_thread_pool` | 3 | Task dispatch; multi-threaded workload distribution across 32 threads; thread pool shutdown synchronization. |
| `AuthenticatorTest` | `test_authenticator` | 27 | RFC 7617 Basic auth; Base64 encoding/decoding; constant-time string comparison; credentials with colons; 407 challenge construction. |
| `HttpForwarderTest` | `test_http_forwarder` | 108 | IPv4/IPv6 SSRF filtering; canonical request rebuilding; hop-by-hop header removal; streaming response forwarding; 10 MB payload limits; timeout deadlines. |
| `ConnectTunnelTest` | `test_connect` | 87 | CONNECT authority parsing; port 443/8443 restrictions; SSRF validation; 200 handshake; non-blocking bidirectional relay; TCP half-close handling under backpressure; idle and lifetime timeouts; concurrency limits. |

### Running Individual Test Binaries
Each test executable can also be run directly for detailed step-by-step reporting:
```bash
./build/test_http_parser
./build/test_thread_pool
./build/test_authenticator
./build/test_http_forwarder
./build/test_connect
```

### Continuous Integration (GitHub Actions)
The repository includes an automated CI workflow configured in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). On every `push` and `pull_request` to the `main` branch, the CI environment:
1. Provisions an `ubuntu-latest` runner with CMake and `g++`.
2. Configures a Release build (`-DCMAKE_BUILD_TYPE=Release`).
3. Compiles the project with `-Wall -Wextra -Wpedantic`.
4. Executes all 5 test suites through `ctest --output-on-failure`.

---

## Performance and Concurrency Benchmark

The project includes a standalone, reproducible benchmark utility ([`scripts/benchmark.py`](scripts/benchmark.py)) to evaluate gateway throughput, latency percentiles, and error handling across varying concurrent client loads.

### Prerequisites & Configuration
- **Python**: Python 3.8+ (uses standard library only: `socket`, `http.server`, `threading`, `time`, `csv`; no external dependencies required).
- **Proxy Build**: The gateway binary must be compiled (`./build/secure_proxy_gateway`).
- **Loopback Testing Mode**: When benchmarking against local test upstreams on loopback interfaces, set `SECURE_PROXY_ALLOW_LOOPBACK=1` or run the script with `--manage-proxy` (which automatically passes this flag to allow loopback destination testing while maintaining self-connection prevention). **Security Notice**: This setting is strictly for isolated local testing and benchmarking; it must never be enabled in a production environment.

### Running the Benchmark

```bash
# 1. Standard run (spawns local mock upstream and runs passes across 1, 5, 10, 20 concurrent clients)
python3 scripts/benchmark.py --manage-proxy

# 2. Custom concurrency and request counts, saving output to CSV:
python3 scripts/benchmark.py --manage-proxy --concurrency 1,5,10,20 --requests 100 --csv build/benchmark_results.csv

# 3. Running against an already running proxy instance:
python3 scripts/benchmark.py --proxy-host 127.0.0.1 --proxy-port 8080 --requests 100

# 4. Validating failure scenarios (unreachable proxy, down upstream, invalid auth):
python3 scripts/benchmark.py --manage-proxy --test-failures
```

### Metrics Reported
- **Concurrency**: Number of concurrent client worker threads.
- **Total Requests / Success / Failed**: Total processed requests and count of HTTP 200 vs failed requests.
- **Err %**: Percentage of requests failing due to HTTP errors (e.g., 502, 403, 407) or client timeouts.
- **Req/s**: Overall throughput (completed requests per second).
- **Avg Latency (ms)**: Arithmetic mean round-trip request latency.
- **p50 Latency (ms)**: Median request latency (50th percentile).
- **p95 Latency (ms)**: Tail latency (95th percentile).

### Interpreting the Results
- **Concurrency Scaling**: As concurrent client threads increase up to the 32-worker pool limit, aggregate throughput scales while p50 latency remains bounded within low milliseconds under local network conditions.
- **Tail Latency (p95)**: Under higher concurrent loads (e.g., 20 concurrent connections), tail latencies reflect OS thread scheduling and connection queueing in the fixed worker thread pool.
- **Error Rates**: A 0.0% error rate confirms that all client requests were successfully authenticated, parsed, and forwarded without connection drops or worker starvation.

### Machine & Environment Context for Reproducibility
When recording or comparing benchmark numbers, record the host environment specifications:
- **Operating System & Kernel**: Linux (e.g., `uname -srm`)
- **CPU & Hardware**: Core count, clock speed, and architecture (e.g., `lscpu`)
- **Compiler & Standard**: GCC or Clang version with `-O3` / `-DCMAKE_BUILD_TYPE=Release`
- **Network Interface**: Local loopback (`lo`) vs external network interface

---

## Limitations

The current implementation has the following documented technical limitations:

- **Plain HTTP Forwarding Deadline**: Forwarding operations enforce a 60-second total deadline for plain HTTP forwarding across request reading, connection, and response streaming.
- **Transparent TLS Passthrough (No Decryption)**: CONNECT supports TLS passthrough/tunneling; the gateway acts as a transparent byte relay and does not perform TLS termination, certificate inspection, or payload inspection.
- **CONNECT Port Restrictions**: CONNECT currently allows only destination ports 443 and 8443.
- **CONNECT Timeouts**: CONNECT tunnels enforce an idle timeout of 60 seconds and a maximum session lifetime cap of 15 minutes.
- **Concurrent Tunnel Limits**: Concurrent CONNECT tunnels are capped at 28 sessions because the implementation utilizes a thread-per-tunnel model on the 32-thread pool.
- **Active Tunnels Delaying SIGTERM Shutdown**: During server shutdown, the worker pool joins all threads sequentially; active CONNECT tunnels and long-lived requests block shutdown until their idle timeout or total lifetime cap expires.
- **Pre-Authentication Worker Exhaustion**: Incoming client connections occupy a worker thread upon `accept()` before request headers are read and authenticated; stalled or slow pre-authentication clients can temporarily occupy available worker pool threads.
- **Lack of Per-User Limits**: Concurrency caps are global rather than per-user; a single authenticated user can saturate all available tunnel slots.
- **TCP Half-Close Behavior**: When the destination server half-closes, the gateway forwards FIN to the client and keeps the tunnel open for ongoing client uploads; an idle client that fails to close its write end after receiving destination FIN keeps the tunnel and worker thread open until the idle timeout expires.
- **Strict SSRF Destination Blocking**: Loopback, private, and reserved destinations remain blocked by strict SSRF protection.
- **Fixed Worker Pool Architecture**: The implementation utilizes a fixed worker pool (32 threads) rather than an event-driven `epoll` or reactor architecture.
- **Synchronous DNS Resolution**: Destination hostname resolution is handled synchronously using `getaddrinfo()`, which relies on operating system resolver timeouts rather than a custom asynchronous timeout.
