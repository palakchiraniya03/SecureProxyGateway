#!/usr/bin/env python3
"""
SecureProxyGateway - Concurrency & Performance Benchmark

Measures proxy throughput, latency percentiles (p50, p95), and error rates
across configurable concurrency levels using a controlled local upstream server.

Usage:
    python3 scripts/benchmark.py [options]

Examples:
    # Run benchmark against an already running proxy:
    python3 scripts/benchmark.py --proxy 127.0.0.1:8080

    # Auto-manage the proxy binary with loopback enabled:
    python3 scripts/benchmark.py --manage-proxy

    # Run custom concurrency levels and request counts:
    python3 scripts/benchmark.py --manage-proxy --concurrency 1,5,10,20 --requests 200 --csv results.csv

    # Run failure scenario validations:
    python3 scripts/benchmark.py --manage-proxy --test-failures

Note:
    SECURE_PROXY_ALLOW_LOOPBACK is strictly intended for isolated local
    benchmarking and testing. It must never be enabled in a production environment.
"""

import argparse
import base64
import csv
import http.server
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple


class MockUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Lightweight HTTP handler for the local benchmark upstream."""
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        payload = b"SecureProxyGateway Benchmark Response OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        # Suppress logging to keep benchmark output clean
        pass


class MockUpstreamServer:
    """Manages an ephemeral local HTTP upstream server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.server = socketserver.ThreadingTCPServer((self.host, port), MockUpstreamHandler)
        self.server.allow_reuse_address = True
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


class ManagedProxy:
    """Spawns and manages the SecureProxyGateway binary for benchmarking."""

    def __init__(self, binary_path: str = "./build/secure_proxy_gateway", port: int = 8080):
        self.binary_path = binary_path
        self.port = port
        self.process: Optional[subprocess.Popen] = None

    def start(self, timeout_sec: float = 3.0) -> None:
        if not os.path.isfile(self.binary_path):
            raise FileNotFoundError(
                f"Proxy executable '{self.binary_path}' not found. Please build the project first."
            )

        env = os.environ.copy()
        env["SECURE_PROXY_ALLOW_LOOPBACK"] = "1"

        self.process = subprocess.Popen(
            [self.binary_path],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait until port is open
        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except (ConnectionRefusedError, OSError):
                time.sleep(0.05)

        raise TimeoutError(f"Proxy failed to start listening on port {self.port} within {timeout_sec}s")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1.0)
            self.process = None


def send_proxy_request(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    path: str = "/bench",
    auth: str = "palak:secureproxy",
    timeout: float = 5.0,
) -> Tuple[bool, int, float, str]:
    """
    Sends a single HTTP proxy request through the proxy gateway.
    Returns: (success: bool, status_code: int, latency_ms: float, error_detail: str)
    """
    auth_header = ""
    if auth:
        b64 = base64.b64encode(auth.encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {b64}\r\n"

    request = (
        f"GET http://{target_host}:{target_port}{path} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"{auth_header}"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    t_start = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((proxy_host, proxy_port))
        s.sendall(request)

        # Read response headers
        resp_buf = bytearray()
        while b"\r\n\r\n" not in resp_buf and len(resp_buf) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp_buf.extend(chunk)

        # Read remaining body if Content-Length present
        header_text = resp_buf.decode("latin1", errors="replace")
        status_code = 0
        lines = header_text.split("\r\n")
        if lines and len(lines[0].split()) >= 2:
            try:
                status_code = int(lines[0].split()[1])
            except ValueError:
                status_code = 0

        # Drain socket until close
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break

        t_end = time.perf_counter()
        latency_ms = (t_end - t_start) * 1000.0

        if status_code == 200:
            return True, status_code, latency_ms, ""
        elif status_code == 403:
            return False, status_code, latency_ms, "403 Forbidden (SSRF blocked)"
        elif status_code == 407:
            return False, status_code, latency_ms, "407 Proxy Authentication Required"
        elif status_code == 502:
            return False, status_code, latency_ms, "502 Bad Gateway (Upstream unreachable)"
        elif status_code == 503:
            return False, status_code, latency_ms, "503 Service Unavailable (Capacity reached)"
        elif status_code == 504:
            return False, status_code, latency_ms, "504 Gateway Timeout"
        else:
            return False, status_code, latency_ms, f"HTTP Status {status_code}"

    except socket.timeout:
        t_end = time.perf_counter()
        return False, 0, (t_end - t_start) * 1000.0, "Socket timeout"
    except ConnectionRefusedError:
        t_end = time.perf_counter()
        return False, 0, (t_end - t_start) * 1000.0, "Proxy connection refused"
    except Exception as e:
        t_end = time.perf_counter()
        return False, 0, (t_end - t_start) * 1000.0, f"Client error: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_concurrency_pass(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    concurrency: int,
    total_requests: int,
    auth: str = "palak:secureproxy",
    timeout: float = 5.0,
) -> Dict[str, object]:
    """Runs a benchmark pass with a fixed number of concurrent workers."""
    latencies: List[float] = []
    error_counts: Dict[str, int] = {}
    success_count = 0
    failure_count = 0
    lock = threading.Lock()

    requests_per_worker = total_requests // concurrency
    remainder = total_requests % concurrency

    def worker(num_reqs: int) -> None:
        nonlocal success_count, failure_count
        for _ in range(num_reqs):
            ok, status, lat_ms, err = send_proxy_request(
                proxy_host, proxy_port, target_host, target_port, auth=auth, timeout=timeout
            )
            with lock:
                latencies.append(lat_ms)
                if ok:
                    success_count += 1
                else:
                    failure_count += 1
                    error_counts[err] = error_counts.get(err, 0) + 1

    threads = []
    t_pass_start = time.perf_counter()
    for i in range(concurrency):
        count = requests_per_worker + (1 if i < remainder else 0)
        t = threading.Thread(target=worker, args=(count,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    t_pass_end = time.perf_counter()

    elapsed_sec = t_pass_end - t_pass_start
    rps = total_requests / elapsed_sec if elapsed_sec > 0 else 0.0

    latencies.sort()
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    p50_lat = latencies[int(len(latencies) * 0.50)] if latencies else 0.0
    p95_lat = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    min_lat = latencies[0] if latencies else 0.0
    max_lat = latencies[-1] if latencies else 0.0
    error_rate = (failure_count / total_requests * 100.0) if total_requests > 0 else 0.0

    return {
        "concurrency": concurrency,
        "total_requests": total_requests,
        "successful_requests": success_count,
        "failed_requests": failure_count,
        "error_rate_pct": error_rate,
        "elapsed_sec": elapsed_sec,
        "throughput_rps": rps,
        "avg_latency_ms": avg_lat,
        "p50_latency_ms": p50_lat,
        "p95_latency_ms": p95_lat,
        "min_latency_ms": min_lat,
        "max_latency_ms": max_lat,
        "errors": error_counts,
    }


def run_failure_scenarios(proxy_host: str, proxy_port: int) -> None:
    """Executes controlled failure scenario validations."""
    print("\n" + "=" * 70)
    print("Running Controlled Failure Scenario Tests")
    print("=" * 70)

    # Scenario 1: Invalid / Unreachable Proxy Endpoint
    print("1. Invalid Proxy Endpoint (127.0.0.1:59999)...", end=" ")
    ok, status, lat, err = send_proxy_request(
        "127.0.0.1", 59999, "127.0.0.1", 80, timeout=1.0
    )
    if not ok and "connection refused" in err.lower():
        print(f"[PASS] Correctly detected unreachable proxy ({err})")
    else:
        print(f"[WARN] Unexpected result: ok={ok}, status={status}, err={err}")

    # Scenario 2: Unavailable Upstream (Proxy running, but upstream port closed)
    print("2. Unavailable Upstream (Closed destination port)...", end=" ")
    ok, status, lat, err = send_proxy_request(
        proxy_host, proxy_port, "127.0.0.1", 59998, timeout=2.0
    )
    if not ok and status in (502, 403):
        # 502 if loopback allowed; 403 if default SSRF mode
        print(f"[PASS] Proxy returned HTTP {status} ({err})")
    else:
        print(f"[WARN] Unexpected result: ok={ok}, status={status}, err={err}")

    # Scenario 3: Invalid Proxy Authentication
    print("3. Invalid Proxy Credentials (baduser:badpass)...", end=" ")
    ok, status, lat, err = send_proxy_request(
        proxy_host, proxy_port, "127.0.0.1", 80, auth="baduser:badpass", timeout=2.0
    )
    if not ok and status == 407:
        print(f"[PASS] Proxy returned HTTP 407 Proxy Authentication Required")
    else:
        print(f"[WARN] Unexpected result: ok={ok}, status={status}, err={err}")

    print("=" * 70 + "\n")


def print_results_table(results: List[Dict[str, object]]) -> None:
    """Prints a formatted ASCII results table."""
    print("\n" + "=" * 88)
    print(
        f"{'Concurrency':<12}{'Requests':<10}{'Success':<10}{'Failed':<8}"
        f"{'Err %':<8}{'Req/s':<12}{'Avg (ms)':<10}{'p50 (ms)':<10}{'p95 (ms)':<10}"
    )
    print("-" * 88)
    for r in results:
        print(
            f"{r['concurrency']:<12}{r['total_requests']:<10}{r['successful_requests']:<10}"
            f"{r['failed_requests']:<8}{r['error_rate_pct']:<8.1f}{r['throughput_rps']:<12.1f}"
            f"{r['avg_latency_ms']:<10.2f}{r['p50_latency_ms']:<10.2f}{r['p95_latency_ms']:<10.2f}"
        )
    print("=" * 88 + "\n")


def export_csv(results: List[Dict[str, object]], csv_path: str) -> None:
    """Exports benchmark metrics to CSV."""
    keys = [
        "concurrency",
        "total_requests",
        "successful_requests",
        "failed_requests",
        "error_rate_pct",
        "throughput_rps",
        "avg_latency_ms",
        "p50_latency_ms",
        "p95_latency_ms",
        "min_latency_ms",
        "max_latency_ms",
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"Results exported successfully to {csv_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecureProxyGateway Concurrency and Performance Benchmark"
    )
    parser.add_argument(
        "--proxy-host", default="127.0.0.1", help="Proxy listening host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--proxy-port", type=int, default=8080, help="Proxy listening port (default: 8080)"
    )
    parser.add_argument(
        "--concurrency",
        default="1,5,10,20",
        help="Comma-separated concurrency levels (default: 1,5,10,20)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=100,
        help="Requests per concurrency level (default: 100)",
    )
    parser.add_argument(
        "--manage-proxy",
        action="store_true",
        help="Auto-start and stop ./build/secure_proxy_gateway with loopback enabled",
    )
    parser.add_argument(
        "--binary-path",
        default="./build/secure_proxy_gateway",
        help="Path to proxy executable when using --manage-proxy",
    )
    parser.add_argument(
        "--csv",
        default="",
        help="Path to export results as CSV (optional)",
    )
    parser.add_argument(
        "--test-failures",
        action="store_true",
        help="Run failure scenario validations before the benchmark",
    )
    args = parser.parse_args()

    try:
        concurrency_levels = [int(c.strip()) for c in args.concurrency.split(",") if c.strip()]
    except ValueError:
        print(f"Error: Invalid concurrency list '{args.concurrency}'. Use format: 1,5,10,20", file=sys.stderr)
        return 1

    # Cleanup handler
    upstream: Optional[MockUpstreamServer] = None
    managed_proxy: Optional[ManagedProxy] = None

    def cleanup() -> None:
        if upstream:
            upstream.stop()
        if managed_proxy:
            managed_proxy.stop()

    def signal_handler(sig: int, frame: object) -> None:
        print("\nBenchmark aborted by user. Cleaning up resources...")
        cleanup()
        sys.exit(130)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Start local upstream
        upstream = MockUpstreamServer()
        print(f"[*] Started local mock upstream on 127.0.0.1:{upstream.port}")

        # Start proxy if requested
        if args.manage_proxy:
            print(f"[*] Starting proxy '{args.binary_path}' on port {args.proxy_port} (loopback testing enabled)...")
            managed_proxy = ManagedProxy(binary_path=args.binary_path, port=args.proxy_port)
            managed_proxy.start()
            print("[*] Proxy started and listening successfully.")

        # Test failure scenarios if requested
        if args.test_failures:
            run_failure_scenarios(args.proxy_host, args.proxy_port)

        print(f"\n[*] Running benchmark passes against proxy at {args.proxy_host}:{args.proxy_port}")
        print(f"[*] Target upstream: 127.0.0.1:{upstream.port}")
        print(f"[*] Concurrency levels: {concurrency_levels}")
        print(f"[*] Requests per pass: {args.requests}\n")

        results = []
        for conc in concurrency_levels:
            print(f"--> Testing concurrency = {conc:<2} ({args.requests} requests)...", end="", flush=True)
            res = run_concurrency_pass(
                proxy_host=args.proxy_host,
                proxy_port=args.proxy_port,
                target_host="127.0.0.1",
                target_port=upstream.port,
                concurrency=conc,
                total_requests=args.requests,
            )
            print(f" Done ({res['throughput_rps']:.1f} req/s, avg {res['avg_latency_ms']:.2f} ms)")
            results.append(res)

        print_results_table(results)

        # Check if there were SSRF block warnings
        for r in results:
            errors = r.get("errors", {})
            for err, count in errors.items():
                if "403 Forbidden" in err:
                    print(
                        f"NOTE: {count} requests received HTTP 403 Forbidden because loopback is blocked by production SSRF.\n"
                        f"Tip: Run the proxy with SECURE_PROXY_ALLOW_LOOPBACK=1 or use --manage-proxy for loopback benchmarking.\n"
                    )
                    break

        if args.csv:
            export_csv(results, args.csv)

        return 0

    finally:
        cleanup()


if __name__ == "__main__":
    sys.exit(main())
