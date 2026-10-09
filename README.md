# SecureProxyGateway

A student-scale C++17 networking and security project.

## Current State

The project features:
- Multithreaded POSIX TCP server on `127.0.0.1:8080` backed by a fixed worker `ThreadPool`.
- Robust HTTP/1.1 request parser supporting forward proxy requests (origin-form, absolute URIs, and CONNECT authority-form).
- HTTP Basic Proxy-Authorization authentication returning `HTTP/1.1 407 Proxy Authentication Required` when unauthenticated.
- Safe plain HTTP forward proxying with strict SSRF protection, canonical request rebuilding, and streamed response forwarding.
- Authenticated HTTP CONNECT tunneling with strict SSRF validation, 200 Connection Established handshake, and non-blocking bidirectional TCP relay.

## Security Notice

> [!CAUTION]
> The configured `Proxy-Authorization` credentials (`palak:secureproxy`) are **demo-only**.
> These credentials must **not** be reused as a real password or in any production environment.
> This authentication mechanism is intended strictly for local and student demonstration purposes.

## Current Limitations

- Forwarding operations currently have a 60-second total deadline for plain HTTP forwarding.
- CONNECT supports TLS passthrough/tunneling; the proxy does not decrypt TLS (transparent byte relay).
- CONNECT currently allows only ports 443 and 8443.
- CONNECT idle timeout is 60 seconds.
- CONNECT total lifetime cap is 15 minutes.
- Concurrent CONNECT tunnels are capped (at 28) because the implementation uses a thread-per-tunnel model.
- Active tunnels delaying SIGTERM shutdown: During server shutdown, the worker pool joins all threads sequentially; active CONNECT tunnels and long-lived requests block shutdown until their idle timeout or total lifetime cap expires.
- Pre-authentication worker exhaustion: Client connections occupy a worker thread upon accept before request reading and authentication; stalled or slow pre-authentication clients can temporarily occupy available worker pool threads.
- Lack of per-user limits: Concurrency caps are global rather than per-user; a single authenticated user can saturate all available tunnel slots.
- TCP half-close behavior: When the destination half-closes, the proxy forwards FIN to the client and keeps the tunnel open for ongoing client uploads; an idle client that does not close its write end after receiving destination FIN will keep the tunnel and worker thread open until the idle timeout expires.
- Loopback, private, and reserved destinations remain blocked by strict SSRF protection.
- The implementation uses a fixed worker pool (32 threads) rather than epoll/event-driven scaling.
- DNS resolution itself has no custom timeout in the current implementation.
