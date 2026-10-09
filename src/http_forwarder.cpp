#include "http_forwarder.h"

#include <iostream>
#include <cstring>
#include <cerrno>
#include <cctype>
#include <vector>
#include <algorithm>
#include <chrono>
#include <limits>
#include <atomic>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace {

std::atomic<size_t> s_active_tunnels{0};
std::atomic<size_t> s_max_tunnels{HttpForwarder::DEFAULT_MAX_CONCURRENT_TUNNELS};

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool send_all(int fd, const char* data, size_t len, std::chrono::steady_clock::time_point deadline) {
    size_t total_sent = 0;
    while (total_sent < len) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return false;
        }
        auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (remaining_ms <= 0) {
            return false;
        }

        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;

        int poll_res = poll(&pfd, 1, static_cast<int>(remaining_ms));
        if (poll_res <= 0) {
            if (poll_res < 0 && errno == EINTR) {
                continue;
            }
            return false;
        }

        ssize_t s = send(fd, data + total_sent, len - total_sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (s < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return false;
        }
        total_sent += static_cast<size_t>(s);
    }
    return true;
}

bool is_ssrf_safe_ipv4(uint32_t ip, uint16_t port, bool allow_loopback) {
    // ip is in host byte order

    // 0.0.0.0/8 (unspecified / current network)
    if ((ip >> 24) == 0) {
        return false;
    }

    // 127.0.0.0/8 (loopback)
    if ((ip >> 24) == 127) {
        if (allow_loopback) {
            // Even when testing loopback, prohibit connecting to gateway's own listening port
            if (port == 8080) {
                return false;
            }
            return true;
        }
        return false;
    }

    // 10.0.0.0/8 (private)
    if ((ip >> 24) == 10) {
        return false;
    }

    // 100.64.0.0/10 (Shared Address Space / Carrier-Grade NAT - RFC 6598)
    if ((ip & 0xFFC00000) == 0x64400000) {
        return false;
    }

    // 172.16.0.0/12 (private: 172.16.0.0 - 172.31.255.255)
    if ((ip & 0xFFF00000) == 0xAC100000) {
        return false;
    }

    // 192.0.0.0/24 (IETF Protocol Assignments - RFC 6890)
    if ((ip & 0xFFFFFF00) == 0xC0000000) {
        return false;
    }

    // 192.168.0.0/16 (private)
    if ((ip & 0xFFFF0000) == 0xC0A80000) {
        return false;
    }

    // 169.254.0.0/16 (link-local)
    if ((ip & 0xFFFF0000) == 0xA9FE0000) {
        return false;
    }

    // 198.18.0.0/15 (Benchmarking - RFC 2544, 198.18.0.0 - 198.19.255.255)
    if ((ip & 0xFFFE0000) == 0xC6120000) {
        return false;
    }

    // 224.0.0.0/4 (Multicast: 14) and 240.0.0.0/4 (Reserved / Future Use / Class E: 15)
    if ((ip >> 28) >= 14) {
        return false;
    }

    return true;
}

bool is_ssrf_safe_ipv6(const struct in6_addr* addr, uint16_t port, bool allow_loopback) {
    const uint8_t* b = reinterpret_cast<const uint8_t*>(addr);

    // :: (unspecified)
    if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
        return false;
    }

    // ::1 (loopback)
    if (IN6_IS_ADDR_LOOPBACK(addr)) {
        if (allow_loopback) {
            if (port == 8080) {
                return false;
            }
            return true;
        }
        return false;
    }

    // fe80::/10 (link-local)
    if (IN6_IS_ADDR_LINKLOCAL(addr) || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)) {
        return false;
    }

    // fec0::/10 (site-local, deprecated RFC 3879)
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) {
        return false;
    }

    // fc00::/7 (unique local address - fc00:: to fdff::)
    if ((b[0] & 0xfe) == 0xfc) {
        return false;
    }

    // 64:ff9b::/96 (IPv4/IPv6 translation - RFC 6052)
    if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
        b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
        b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0) {
        return false; // Block 64:ff9b::/96
    }

    // 2002::/16 (6to4 - RFC 3056)
    if (b[0] == 0x20 && b[1] == 0x02) {
        return false; // Block 2002::/16
    }

    // 2001::/32 (Teredo - RFC 4380)
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) {
        return false; // Block 2001::/32
    }

    // IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        uint32_t ip4 = (static_cast<uint32_t>(b[12]) << 24) |
                       (static_cast<uint32_t>(b[13]) << 16) |
                       (static_cast<uint32_t>(b[14]) << 8)  |
                        static_cast<uint32_t>(b[15]);
        return is_ssrf_safe_ipv4(ip4, port, allow_loopback);
    }

    // IPv4-compatible IPv6 (::x.x.x.x)
    bool is_v4_compat = true;
    for (int i = 0; i < 12; ++i) {
        if (b[i] != 0) {
            is_v4_compat = false;
            break;
        }
    }
    if (is_v4_compat) {
        uint32_t ip4 = (static_cast<uint32_t>(b[12]) << 24) |
                       (static_cast<uint32_t>(b[13]) << 16) |
                       (static_cast<uint32_t>(b[14]) << 8)  |
                        static_cast<uint32_t>(b[15]);
        return is_ssrf_safe_ipv4(ip4, port, allow_loopback);
    }

    // Multicast (ff00::/8)
    if (b[0] == 0xff) {
        return false;
    }

    return true;
}

int connect_with_deadline(const struct addrinfo* ai, std::chrono::steady_clock::time_point deadline) {
    int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) {
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    int res = connect(sock, ai->ai_addr, ai->ai_addrlen);
    if (res < 0) {
        if (errno == EINPROGRESS) {
            struct pollfd pfd{};
            pfd.fd = sock;
            pfd.events = POLLOUT;

            while (true) {
                auto now = std::chrono::steady_clock::now();
                if (now >= deadline) {
                    close(sock);
                    return -1;
                }
                auto rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
                if (rem_ms <= 0) {
                    close(sock);
                    return -1;
                }

                int poll_res = poll(&pfd, 1, static_cast<int>(rem_ms));
                if (poll_res < 0 && errno == EINTR) {
                    continue;
                }
                if (poll_res <= 0) {
                    close(sock);
                    return -1;
                }

                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                    close(sock);
                    return -1;
                }
                break;
            }
        } else {
            close(sock);
            return -1;
        }
    }

    // Restore blocking mode
    fcntl(sock, F_SETFL, flags);

    // Set socket receive and send timeouts
    struct timeval tv{};
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    return sock;
}

} // namespace

HttpForwarder::HttpForwarder(bool allow_loopback_for_testing)
    : allow_loopback_for_testing_(allow_loopback_for_testing) {}

bool HttpForwarder::is_ssrf_safe(const struct sockaddr* addr, socklen_t addrlen, bool allow_loopback) {
    if (!addr) {
        return false;
    }
    if (addr->sa_family == AF_INET) {
        if (addrlen < sizeof(struct sockaddr_in)) {
            return false;
        }
        const auto* sin = reinterpret_cast<const struct sockaddr_in*>(addr);
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        uint16_t port = ntohs(sin->sin_port);
        return is_ssrf_safe_ipv4(ip, port, allow_loopback);
    } else if (addr->sa_family == AF_INET6) {
        if (addrlen < sizeof(struct sockaddr_in6)) {
            return false;
        }
        const auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
        uint16_t port = ntohs(sin6->sin6_port);
        return is_ssrf_safe_ipv6(&sin6->sin6_addr, port, allow_loopback);
    }
    return false;
}

std::string HttpForwarder::rebuild_request(const HttpRequest& req, std::string_view body) {
    std::string out;
    out.reserve(512 + body.size());

    // 1. Origin-form request line
    std::string path = req.path;
    if (path.empty()) {
        path = "/";
    }
    out += req.method + " " + path + " HTTP/1.1\r\n";

    // 2. Canonical Host header based on req.host and req.port
    bool is_ipv6 = (req.host.find(':') != std::string::npos);
    std::string formatted_host;
    if (is_ipv6 && (req.host.front() != '[')) {
        formatted_host = "[" + req.host + "]";
    } else {
        formatted_host = req.host;
    }

    if (req.port == 80) {
        out += "Host: " + formatted_host + "\r\n";
    } else {
        out += "Host: " + formatted_host + ":" + std::to_string(req.port) + "\r\n";
    }

    // 3. Forward other request headers (excluding Host, Proxy-Authorization, Proxy-Connection, Connection)
    bool content_length_present = false;
    for (const auto& [name, value] : req.headers) {
        if (iequals(name, "Host") ||
            iequals(name, "Proxy-Authorization") ||
            iequals(name, "Proxy-Connection") ||
            iequals(name, "Connection") ||
            iequals(name, "Expect") ||
            iequals(name, "Upgrade") ||
            iequals(name, "TE") ||
            iequals(name, "Trailer") ||
            iequals(name, "Keep-Alive")) {
            continue;
        }
        if (iequals(name, "Content-Length")) {
            content_length_present = true;
            out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        } else {
            out += name + ": " + value + "\r\n";
        }
    }

    // If body is present and Content-Length wasn't forwarded from headers, add it
    if (!body.empty() && !content_length_present) {
        out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }

    // 4. Connection: close
    out += "Connection: close\r\n";

    // 5. Header terminator
    out += "\r\n";

    // 6. Body
    if (!body.empty()) {
        out.append(body.data(), body.size());
    }

    return out;
}

ForwardResult HttpForwarder::forward(const HttpRequest& req,
                                     std::string_view initial_body_data,
                                     int client_fd,
                                     std::optional<std::chrono::steady_clock::time_point> deadline) {
    // 1. Plain HTTP forwarder must reject HTTPS absolute-form targets
    std::string_view target_view = req.request_target;
    if (target_view.size() >= 8 && iequals(target_view.substr(0, 8), "https://")) {
        std::string resp_501 = make_501_https_response();
        send(client_fd, resp_501.data(), resp_501.size(), MSG_NOSIGNAL);
        return ForwardResult::NotImplemented;
    }

    // 2. Request body size limit check (MUST FIX 1)
    if (req.content_length.has_value() && *req.content_length > MAX_BODY_BYTES) {
        std::string resp_413 = make_413_response();
        send(client_fd, resp_413.data(), resp_413.size(), MSG_NOSIGNAL);
        return ForwardResult::PayloadTooLarge;
    }

    // 3. Establish ONE absolute forwarding deadline (MUST FIX 2)
    const auto total_deadline = deadline.value_or(
        std::chrono::steady_clock::now() + std::chrono::seconds(60)
    );

    // 4. Handle Request Body if Content-Length is present (A. Request Body Reading)
    std::string body(initial_body_data);
    if (req.content_length.has_value()) {
        size_t target_len = *req.content_length;
        if (body.size() > target_len) {
            std::string resp_400 = HttpParser::make_400_response();
            send(client_fd, resp_400.data(), resp_400.size(), MSG_NOSIGNAL);
            return ForwardResult::IncompleteRequestBody;
        }

        while (body.size() < target_len) {
            auto now = std::chrono::steady_clock::now();
            if (now >= total_deadline) {
                std::string resp_400 = HttpParser::make_400_response();
                send(client_fd, resp_400.data(), resp_400.size(), MSG_NOSIGNAL);
                return ForwardResult::IncompleteRequestBody;
            }
            auto rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_deadline - now).count();
            if (rem_ms <= 0) {
                std::string resp_400 = HttpParser::make_400_response();
                send(client_fd, resp_400.data(), resp_400.size(), MSG_NOSIGNAL);
                return ForwardResult::IncompleteRequestBody;
            }

            size_t needed = target_len - body.size();
            char chunk[2048];
            size_t to_read = std::min(sizeof(chunk), needed);

            struct pollfd pfd{};
            pfd.fd = client_fd;
            pfd.events = POLLIN;

            int poll_res = poll(&pfd, 1, static_cast<int>(rem_ms));
            if (poll_res <= 0) {
                if (poll_res < 0 && errno == EINTR) {
                    continue;
                }
                std::string resp_400 = HttpParser::make_400_response();
                send(client_fd, resp_400.data(), resp_400.size(), MSG_NOSIGNAL);
                return ForwardResult::IncompleteRequestBody;
            }

            ssize_t bytes_read = recv(client_fd, chunk, to_read, 0);
            if (bytes_read <= 0) {
                if (bytes_read < 0 && errno == EINTR) {
                    continue;
                }
                std::string resp_400 = HttpParser::make_400_response();
                send(client_fd, resp_400.data(), resp_400.size(), MSG_NOSIGNAL);
                return ForwardResult::IncompleteRequestBody;
            }

            body.append(chunk, static_cast<size_t>(bytes_read));
        }
    } else {
        // No Content-Length; no body expected
        body.clear();
    }

    // 5. Resolve destination using getaddrinfo()
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(req.port);

    int gai_err = getaddrinfo(req.host.c_str(), port_str.c_str(), &hints, &res);
    if (gai_err != 0 || !res) {
        std::string resp_502 = make_502_response();
        send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
        return ForwardResult::DnsFailure;
    }

    // 6. SSRF destination validation: inspect every resolved address
    std::vector<struct addrinfo*> safe_addrs;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (is_ssrf_safe(p->ai_addr, p->ai_addrlen, allow_loopback_for_testing_)) {
            safe_addrs.push_back(p);
        }
    }

    if (safe_addrs.empty()) {
        freeaddrinfo(res);
        std::string resp_403 = make_403_response();
        send(client_fd, resp_403.data(), resp_403.size(), MSG_NOSIGNAL);
        return ForwardResult::SsrfBlocked;
    }

    // 7. Outbound connect: overall connection deadline (~10 seconds or bounded by total_deadline)
    auto connect_deadline = std::min(
        total_deadline,
        std::chrono::steady_clock::now() + std::chrono::seconds(10)
    );

    constexpr size_t MAX_CONNECT_ADDRS = 4;
    size_t tried = 0;
    int dest_fd = -1;

    for (struct addrinfo* safe_ai : safe_addrs) {
        if (tried++ >= MAX_CONNECT_ADDRS) {
            break;
        }
        auto now = std::chrono::steady_clock::now();
        if (now >= connect_deadline) {
            break;
        }
        // Per-address attempt budget: ~3 seconds or remaining overall deadline
        auto addr_deadline = std::min(
            connect_deadline,
            now + std::chrono::seconds(3)
        );
        dest_fd = connect_with_deadline(safe_ai, addr_deadline);
        if (dest_fd >= 0) {
            break;
        }
    }
    freeaddrinfo(res);

    if (dest_fd < 0) {
        std::string resp_502 = make_502_response();
        send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
        return ForwardResult::ConnectFailure;
    }

    // 8. Rebuild and send outbound request (C. Outbound send_all with total_deadline)
    std::string outbound_req = rebuild_request(req, body);
    if (!send_all(dest_fd, outbound_req.data(), outbound_req.size(), total_deadline)) {
        close(dest_fd);
        std::string resp_502 = make_502_response();
        send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
        return ForwardResult::SendFailure;
    }

    // 9. Receive response and stream it to the client (B. Response Reading with total_deadline)
    char buffer[8192];
    bool bytes_forwarded = false;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= total_deadline) {
            close(dest_fd);
            if (!bytes_forwarded) {
                std::string resp_504 = make_504_response();
                send(client_fd, resp_504.data(), resp_504.size(), MSG_NOSIGNAL);
            }
            return ForwardResult::Timeout;
        }

        auto rem_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_deadline - now).count();
        if (rem_ms <= 0) {
            close(dest_fd);
            if (!bytes_forwarded) {
                std::string resp_504 = make_504_response();
                send(client_fd, resp_504.data(), resp_504.size(), MSG_NOSIGNAL);
            }
            return ForwardResult::Timeout;
        }

        struct pollfd pfd{};
        pfd.fd = dest_fd;
        pfd.events = POLLIN;

        int poll_res = poll(&pfd, 1, static_cast<int>(rem_ms));
        if (poll_res == 0) {
            // Deadline expired
            close(dest_fd);
            if (!bytes_forwarded) {
                std::string resp_504 = make_504_response();
                send(client_fd, resp_504.data(), resp_504.size(), MSG_NOSIGNAL);
            }
            return ForwardResult::Timeout;
        }
        if (poll_res < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(dest_fd);
            if (!bytes_forwarded) {
                std::string resp_502 = make_502_response();
                send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
            }
            return ForwardResult::RecvFailure;
        }

        ssize_t bytes_read = recv(dest_fd, buffer, sizeof(buffer), 0);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(dest_fd);
            if (!bytes_forwarded) {
                std::string resp_502 = make_502_response();
                send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
            }
            return ForwardResult::RecvFailure;
        }

        if (bytes_read == 0) {
            // Destination closed connection; response complete
            break;
        }

        bytes_forwarded = true;
        if (!send_all(client_fd, buffer, static_cast<size_t>(bytes_read), total_deadline)) {
            close(dest_fd);
            return ForwardResult::ClientDisconnect;
        }
    }

    close(dest_fd);
    return ForwardResult::Success;
}

std::string HttpForwarder::make_403_response() {
    const std::string body = "Forbidden\n";
    return "HTTP/1.1 403 Forbidden\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

std::string HttpForwarder::make_413_response() {
    const std::string body = "Payload Too Large\n";
    return "HTTP/1.1 413 Payload Too Large\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

std::string HttpForwarder::make_501_https_response() {
    const std::string body = "HTTPS proxying requires CONNECT tunneling\n";
    return "HTTP/1.1 501 Not Implemented\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

std::string HttpForwarder::make_502_response() {
    const std::string body = "Bad Gateway\n";
    return "HTTP/1.1 502 Bad Gateway\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

std::string HttpForwarder::make_503_response() {
    const std::string body = "Service Unavailable\n";
    return "HTTP/1.1 503 Service Unavailable\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

std::string HttpForwarder::make_504_response() {
    const std::string body = "Gateway Timeout\n";
    return "HTTP/1.1 504 Gateway Timeout\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

bool HttpForwarder::try_acquire_tunnel() {
    size_t cur = s_active_tunnels.load(std::memory_order_relaxed);
    while (true) {
        if (cur >= s_max_tunnels.load(std::memory_order_relaxed)) {
            return false;
        }
        if (s_active_tunnels.compare_exchange_weak(cur, cur + 1,
                                                   std::memory_order_relaxed,
                                                   std::memory_order_relaxed)) {
            return true;
        }
    }
}

void HttpForwarder::release_tunnel() {
    s_active_tunnels.fetch_sub(1, std::memory_order_relaxed);
}

size_t HttpForwarder::active_tunnels() {
    return s_active_tunnels.load(std::memory_order_relaxed);
}

void HttpForwarder::set_max_concurrent_tunnels(size_t max) {
    s_max_tunnels.store(max, std::memory_order_relaxed);
}

ForwardResult HttpForwarder::forward_connect(
    const HttpRequest& req,
    std::string_view initial_client_data,
    int client_fd,
    std::chrono::milliseconds idle_timeout,
    std::chrono::milliseconds total_timeout) {

    if (req.method != "CONNECT") {
        return ForwardResult::NotImplemented;
    }

    // Port restriction: production CONNECT requests allow only 443 and 8443
    if (!allow_loopback_for_testing_) {
        if (!is_allowed_connect_port(req.port)) {
            std::string resp_403 = make_403_response();
            send(client_fd, resp_403.data(), resp_403.size(), MSG_NOSIGNAL);
            return ForwardResult::SsrfBlocked;
        }
    }

    // 1. Resolve destination hostname using getaddrinfo()
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(req.port);

    int gai_err = getaddrinfo(req.host.c_str(), port_str.c_str(), &hints, &res);
    if (gai_err != 0 || !res) {
        std::string resp_502 = make_502_response();
        send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
        return ForwardResult::DnsFailure;
    }

    // 2. SSRF validation: inspect every resolved address
    std::vector<struct addrinfo*> safe_addrs;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (is_ssrf_safe(p->ai_addr, p->ai_addrlen, allow_loopback_for_testing_)) {
            safe_addrs.push_back(p);
        }
    }

    if (safe_addrs.empty()) {
        freeaddrinfo(res);
        std::string resp_403 = make_403_response();
        send(client_fd, resp_403.data(), resp_403.size(), MSG_NOSIGNAL);
        return ForwardResult::SsrfBlocked;
    }

    // 3. Outbound connect:
    // - overall outbound connection deadline of ~10 seconds
    // - per-address attempt budget of ~3 seconds
    // - try at most 4 validated addresses
    auto connect_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    constexpr size_t MAX_CONNECT_ADDRS = 4;
    size_t tried = 0;
    int dest_fd = -1;
    bool timed_out = false;

    for (struct addrinfo* safe_ai : safe_addrs) {
        if (tried++ >= MAX_CONNECT_ADDRS) {
            break;
        }
        auto now = std::chrono::steady_clock::now();
        if (now >= connect_deadline) {
            timed_out = true;
            break;
        }
        auto per_addr_deadline = std::min(
            connect_deadline,
            now + std::chrono::seconds(3)
        );
        dest_fd = connect_with_deadline(safe_ai, per_addr_deadline);
        if (dest_fd >= 0) {
            break;
        }
    }
    freeaddrinfo(res);

    if (dest_fd < 0) {
        if (timed_out || std::chrono::steady_clock::now() >= connect_deadline) {
            std::string resp_504 = make_504_response();
            send(client_fd, resp_504.data(), resp_504.size(), MSG_NOSIGNAL);
            return ForwardResult::Timeout;
        }
        std::string resp_502 = make_502_response();
        send(client_fd, resp_502.data(), resp_502.size(), MSG_NOSIGNAL);
        return ForwardResult::ConnectFailure;
    }

    // 4. Send 200 Connection Established once outbound connection is ready
    const std::string resp_200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (!send_all(client_fd, resp_200.data(), resp_200.size(), std::chrono::steady_clock::now() + std::chrono::seconds(5))) {
        close(dest_fd);
        return ForwardResult::ClientDisconnect;
    }

    // 5. Bidirectional TCP relay
    ForwardResult relay_res = relay_tunnel(client_fd, dest_fd, initial_client_data, idle_timeout, total_timeout);
    close(dest_fd);
    return relay_res;
}

ForwardResult HttpForwarder::relay_tunnel(
    int client_fd,
    int dest_fd,
    std::string_view initial_client_data,
    std::chrono::milliseconds idle_timeout,
    std::chrono::milliseconds total_timeout) {

    int client_orig_flags = fcntl(client_fd, F_GETFL, 0);
    int dest_orig_flags = fcntl(dest_fd, F_GETFL, 0);

    if (client_orig_flags >= 0) {
        fcntl(client_fd, F_SETFL, client_orig_flags | O_NONBLOCK);
    }
    if (dest_orig_flags >= 0) {
        fcntl(dest_fd, F_SETFL, dest_orig_flags | O_NONBLOCK);
    }

    constexpr size_t BUFFER_SIZE = 16384;
    std::vector<char> c2d_buf;
    if (!initial_client_data.empty()) {
        c2d_buf.assign(initial_client_data.begin(), initial_client_data.end());
    }
    size_t c2d_offset = 0;
    bool client_eof = false;
    bool client_shutdown_sent = false;

    std::vector<char> d2c_buf;
    size_t d2c_offset = 0;
    bool dest_eof = false;
    bool dest_shutdown_sent = false;

    auto start_time = std::chrono::steady_clock::now();
    auto last_activity = start_time;
    auto total_deadline = start_time + total_timeout;

    char read_chunk[BUFFER_SIZE];
    ForwardResult final_result = ForwardResult::Success;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= total_deadline) {
            final_result = ForwardResult::Timeout;
            break;
        }
        if (now - last_activity >= idle_timeout) {
            final_result = ForwardResult::Timeout;
            break;
        }

        auto rem_total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_deadline - now).count();
        auto rem_idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>((last_activity + idle_timeout) - now).count();

        long long poll_ms_ll = std::min(rem_total_ms, rem_idle_ms);
        if (poll_ms_ll <= 0) {
            final_result = ForwardResult::Timeout;
            break;
        }
        int poll_ms = static_cast<int>(std::min(poll_ms_ll, static_cast<long long>(std::numeric_limits<int>::max())));

        struct pollfd pfds[2]{};
        pfds[0].fd = client_fd;
        pfds[1].fd = dest_fd;

        // Client socket events
        if (!client_eof && c2d_offset >= c2d_buf.size()) {
            pfds[0].events |= POLLIN;
        }
        if (d2c_offset < d2c_buf.size()) {
            pfds[0].events |= POLLOUT;
        }

        // Destination socket events
        if (!dest_eof && d2c_offset >= d2c_buf.size()) {
            pfds[1].events |= POLLIN;
        }
        if (c2d_offset < c2d_buf.size()) {
            pfds[1].events |= POLLOUT;
        }

        if (pfds[1].events == 0) pfds[1].fd = -1;

        // Termination checks: Both sides reached EOF and buffered data drained
        if (client_eof && c2d_offset >= c2d_buf.size() && dest_eof && d2c_offset >= d2c_buf.size()) {
            break;
        }
        if (pfds[0].events == 0 && pfds[1].events == 0) {
            break;
        }

        int poll_res = poll(pfds, 2, poll_ms);
        if (poll_res < 0) {
            if (errno == EINTR) {
                continue;
            }
            final_result = ForwardResult::RecvFailure;
            break;
        }
        if (poll_res == 0) {
            final_result = ForwardResult::Timeout;
            break;
        }

        // 1. Inspect immediately for fatal error (e.g. RST/POLLERR) or invalid descriptor
        bool fatal = false;
        for (int i = 0; i < 2; ++i) {
            short r = pfds[i].revents;
            if (r & (POLLNVAL | POLLERR)) {
                fatal = true;
                final_result = ForwardResult::RecvFailure;
                break;
            }
        }

        if (fatal) {
            break;
        }

        // Writes (POLLOUT)
        if ((pfds[1].revents & POLLOUT) && c2d_offset < c2d_buf.size()) {
            ssize_t s = send(dest_fd, c2d_buf.data() + c2d_offset, c2d_buf.size() - c2d_offset, MSG_NOSIGNAL);
            if (s > 0) {
                c2d_offset += static_cast<size_t>(s);
                last_activity = std::chrono::steady_clock::now();
                if (c2d_offset >= c2d_buf.size()) {
                    c2d_buf.clear();
                    c2d_offset = 0;
                    if (client_eof && !client_shutdown_sent) {
                        shutdown(dest_fd, SHUT_WR);
                        client_shutdown_sent = true;
                    }
                }
            } else if (s < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    final_result = ForwardResult::SendFailure;
                    break;
                }
            }
        }

        if ((pfds[0].revents & POLLOUT) && d2c_offset < d2c_buf.size()) {
            ssize_t s = send(client_fd, d2c_buf.data() + d2c_offset, d2c_buf.size() - d2c_offset, MSG_NOSIGNAL);
            if (s > 0) {
                d2c_offset += static_cast<size_t>(s);
                last_activity = std::chrono::steady_clock::now();
                if (d2c_offset >= d2c_buf.size()) {
                    d2c_buf.clear();
                    d2c_offset = 0;
                    if (dest_eof && !dest_shutdown_sent) {
                        shutdown(client_fd, SHUT_WR);
                        dest_shutdown_sent = true;
                    }
                }
            } else if (s < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    final_result = ForwardResult::ClientDisconnect;
                    break;
                }
            }
        }

        // Reads (POLLIN / POLLHUP / POLLERR)
        if ((pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) && !client_eof && c2d_offset >= c2d_buf.size()) {
            ssize_t n = recv(client_fd, read_chunk, sizeof(read_chunk), 0);
            if (n > 0) {
                c2d_buf.assign(read_chunk, read_chunk + n);
                c2d_offset = 0;
                last_activity = std::chrono::steady_clock::now();
            } else if (n == 0) {
                client_eof = true;
                if (c2d_offset >= c2d_buf.size() && !client_shutdown_sent) {
                    shutdown(dest_fd, SHUT_WR);
                    client_shutdown_sent = true;
                }
            } else {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    client_eof = true;
                    final_result = ForwardResult::ClientDisconnect;
                    break;
                }
            }
        }

        if ((pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) && !dest_eof && d2c_offset >= d2c_buf.size()) {
            ssize_t n = recv(dest_fd, read_chunk, sizeof(read_chunk), 0);
            if (n > 0) {
                d2c_buf.assign(read_chunk, read_chunk + n);
                d2c_offset = 0;
                last_activity = std::chrono::steady_clock::now();
            } else if (n == 0) {
                dest_eof = true;
                if (d2c_offset >= d2c_buf.size() && !dest_shutdown_sent) {
                    shutdown(client_fd, SHUT_WR);
                    dest_shutdown_sent = true;
                }
            } else {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    dest_eof = true;
                    final_result = ForwardResult::RecvFailure;
                    break;
                }
            }
        }

        // 4. Handle remaining unconsumed POLLHUP where POLLIN was not polled
        for (int i = 0; i < 2; ++i) {
            short r = pfds[i].revents;
            bool already_eof = (i == 0 ? client_eof : dest_eof);
            if ((r & POLLHUP) && !(pfds[i].events & POLLIN)) {
                if (!already_eof) {
                    if (i == 0) {
                        if (!(pfds[1].revents & POLLOUT)) {
                            fatal = true;
                            final_result = ForwardResult::RecvFailure;
                            break;
                        }
                    } else {
                        if (!(pfds[0].revents & POLLOUT)) {
                            fatal = true;
                            final_result = ForwardResult::RecvFailure;
                            break;
                        }
                    }
                    continue;
                }
                if (i == 0 && !dest_eof && d2c_offset >= d2c_buf.size()) {
                    fatal = true;
                    final_result = ForwardResult::RecvFailure;
                    break;
                }
                if (i == 1 && c2d_offset < c2d_buf.size()) {
                    fatal = true;
                    final_result = ForwardResult::SendFailure;
                    break;
                }
            }
        }
        if (fatal) {
            break;
        }
    }

    if (client_orig_flags >= 0) {
        fcntl(client_fd, F_SETFL, client_orig_flags);
    }
    if (dest_orig_flags >= 0) {
        fcntl(dest_fd, F_SETFL, dest_orig_flags);
    }

    return final_result;
}
