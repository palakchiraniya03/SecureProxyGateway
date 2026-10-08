# SecureProxyGateway

A student-scale C++17 networking and security project.

## Current State

The project features:
- Multithreaded POSIX TCP server on `127.0.0.1:8080` backed by a fixed worker `ThreadPool`.
- Robust HTTP/1.1 request parser supporting forward proxy requests (origin-form, absolute URIs, and CONNECT authority-form).
- HTTP Basic Proxy-Authorization authentication returning `HTTP/1.1 407 Proxy Authentication Required` when unauthenticated.

## Security Notice

> [!CAUTION]
> The configured `Proxy-Authorization` credentials (`palak:secureproxy`) are **demo-only**.
> These credentials must **not** be reused as a real password or in any production environment.
> This authentication mechanism is intended strictly for local and student demonstration purposes.
