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

    // Helpers to create standard HTTP error responses
    static std::string make_403_response();
    static std::string make_413_response();
    static std::string make_501_https_response();
    static std::string make_502_response();
    static std::string make_504_response();

    bool allows_loopback_for_testing() const { return allow_loopback_for_testing_; }

private:
    bool allow_loopback_for_testing_{false};
};

#endif // HTTP_FORWARDER_H
