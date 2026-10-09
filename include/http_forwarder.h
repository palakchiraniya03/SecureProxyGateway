#ifndef HTTP_FORWARDER_H
#define HTTP_FORWARDER_H

#include "http_parser.h"
#include <string>
#include <string_view>
#include <cstdint>
#include <chrono>
#include <optional>
#include <sys/socket.h>
#include <netinet/in.h>

enum class ForwardResult {
    Success,
    SsrfBlocked,
    DnsFailure,
    ConnectFailure,
    SendFailure,
    RecvFailure,
    IncompleteRequestBody,
    PayloadTooLarge,
    Timeout,
    NotImplemented,
    ClientDisconnect
};

class HttpForwarder {
public:
    static constexpr size_t MAX_BODY_BYTES = 10 * 1024 * 1024; // 10 MB

    explicit HttpForwarder(bool allow_loopback_for_testing = false);

    // Checks if a resolved sockaddr is safe according to SSRF protection rules
    static bool is_ssrf_safe(const struct sockaddr* addr, socklen_t addrlen, bool allow_loopback = false);

    // Rebuilds the HTTP request in origin-form suitable for sending to the destination
    static std::string rebuild_request(const HttpRequest& req, std::string_view body);

    // Forwards the authenticated HTTP request to the destination server,
    // streaming the destination response back to client_fd.
    // initial_body_data contains any bytes already read after headers (request_buffer.substr(req.header_length))
    // A single absolute deadline is used across all forwarding phases (body read, connect, send, response stream)
    ForwardResult forward(const HttpRequest& req,
                          std::string_view initial_body_data,
                          int client_fd,
                          std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt);

    // Forwards an authenticated CONNECT request:
    // Resolves destination, checks SSRF, connects to destination,
    // sends "HTTP/1.1 200 Connection Established\r\n\r\n", and relays bidirectional traffic.
    // Total lifetime cap is 15 minutes (900 seconds); idle timeout is 60 seconds.
    ForwardResult forward_connect(
        const HttpRequest& req,
        std::string_view initial_client_data,
        int client_fd,
        std::chrono::milliseconds idle_timeout = std::chrono::seconds(60),
        std::chrono::milliseconds total_timeout = std::chrono::seconds(900));

    // Bidirectional TCP relay helper
    static ForwardResult relay_tunnel(
        int client_fd,
        int dest_fd,
        std::string_view initial_client_data = "",
        std::chrono::milliseconds idle_timeout = std::chrono::seconds(60),
        std::chrono::milliseconds total_timeout = std::chrono::seconds(900));

    // Helpers to create standard HTTP error responses
    static std::string make_403_response();
    static std::string make_413_response();
    static std::string make_501_https_response();
    static std::string make_502_response();
    static std::string make_503_response();
    static std::string make_504_response();

    // CONNECT port restriction helper: allows only 443 and 8443
    static bool is_allowed_connect_port(uint16_t port) {
        return port == 443 || port == 8443;
    }

    // Concurrent CONNECT tunnel limiting
    static constexpr size_t DEFAULT_MAX_CONCURRENT_TUNNELS = 28;
    static bool try_acquire_tunnel();
    static void release_tunnel();
    static size_t active_tunnels();
    static void set_max_concurrent_tunnels(size_t max);

    bool allows_loopback_for_testing() const { return allow_loopback_for_testing_; }

private:
    bool allow_loopback_for_testing_{false};
};

#endif // HTTP_FORWARDER_H
