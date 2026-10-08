#include "http_forwarder.h"

#include <iostream>
#include <cstring>
#include <cerrno>
#include <vector>
#include <algorithm>
#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace {

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
            if (ip == 0x7F000001 && port == 8080) {
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
        uint32_t ip4 = (static_cast<uint32_t>(b[12]) << 24) |
                       (static_cast<uint32_t>(b[13]) << 16) |
                       (static_cast<uint32_t>(b[14]) << 8)  |
                        static_cast<uint32_t>(b[15]);
        // Also classify embedded IPv4
        is_ssrf_safe_ipv4(ip4, port, allow_loopback);
        return false; // Block 64:ff9b::/96
    }

    // 2002::/16 (6to4 - RFC 3056)
    if (b[0] == 0x20 && b[1] == 0x02) {
        uint32_t ip4 = (static_cast<uint32_t>(b[2]) << 24) |
                       (static_cast<uint32_t>(b[3]) << 16) |
                       (static_cast<uint32_t>(b[4]) << 8)  |
                        static_cast<uint32_t>(b[5]);
        // Also classify embedded IPv4
        is_ssrf_safe_ipv4(ip4, port, allow_loopback);
        return false; // Block 2002::/16
    }

    // 2001::/32 (Teredo - RFC 4380)
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) {
        uint32_t server_ip4 = (static_cast<uint32_t>(b[4]) << 24) |
                              (static_cast<uint32_t>(b[5]) << 16) |
                              (static_cast<uint32_t>(b[6]) << 8)  |
                               static_cast<uint32_t>(b[7]);
        uint32_t client_ip4 = (~static_cast<uint32_t>(b[12]) << 24) |
                              (~static_cast<uint32_t>(b[13]) << 16) |
                              (~static_cast<uint32_t>(b[14]) << 8)  |
                               ~static_cast<uint32_t>(b[15]);
        // Classify embedded IPv4s
        is_ssrf_safe_ipv4(server_ip4, port, allow_loopback);
        is_ssrf_safe_ipv4(client_ip4, port, allow_loopback);
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
            iequals(name, "Connection")) {
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
        dest_fd = connect_with_deadline(safe_ai, connect_deadline);
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

std::string HttpForwarder::make_504_response() {
    const std::string body = "Gateway Timeout\n";
    return "HTTP/1.1 504 Gateway Timeout\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}
