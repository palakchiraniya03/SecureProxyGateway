#include "http_forwarder.h"
#include "http_parser.h"
#include "authenticator.h"

#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <functional>
#include <cstring>
#include <cassert>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

namespace {

int g_passed = 0;
int g_failed = 0;

void assert_test(bool condition, const std::string& test_name, const std::string& detail = "") {
    if (condition) {
        std::cout << "[PASS] " << test_name << std::endl;
        g_passed++;
    } else {
        std::cout << "[FAIL] " << test_name;
        if (!detail.empty()) {
            std::cout << " (" << detail << ")";
        }
        std::cout << std::endl;
        g_failed++;
    }
}

// Lightweight mock destination server running on loopback with an ephemeral port
class MockHttpServer {
public:
    explicit MockHttpServer(std::function<void(int client_fd)> handler)
        : handler_(std::move(handler)) {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0) {
            perror("MockHttpServer bind failed");
        }
        if (listen(server_fd_, 5) < 0) {
            perror("MockHttpServer listen failed");
        }

        socklen_t len = sizeof(sin);
        getsockname(server_fd_, reinterpret_cast<struct sockaddr*>(&sin), &len);
        port_ = ntohs(sin.sin_port);

        worker_ = std::thread([this]() {
            while (running_) {
                struct pollfd pfd{};
                pfd.fd = server_fd_;
                pfd.events = POLLIN;
                int r = poll(&pfd, 1, 100);
                if (r > 0 && (pfd.revents & POLLIN)) {
                    int cfd = accept(server_fd_, nullptr, nullptr);
                    if (cfd >= 0) {
                        handler_(cfd);
                        close(cfd);
                    }
                }
            }
        });
    }

    ~MockHttpServer() {
        running_ = false;
        if (worker_.joinable()) {
            worker_.join();
        }
        if (server_fd_ >= 0) {
            close(server_fd_);
        }
    }

    uint16_t port() const { return port_; }

private:
    std::function<void(int client_fd)> handler_;
    int server_fd_{-1};
    uint16_t port_{0};
    std::atomic<bool> running_{true};
    std::thread worker_;
};

std::string read_all_from_socket(int fd) {
    std::string out;
    char buf[1024];
    while (true) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

} // namespace

int main() {
    signal(SIGPIPE, SIG_IGN);
    std::cout << "Running HTTP Forwarder Test Suite..." << std::endl;

    // Test 1: SSRF IPv4 unit validations
    {
        struct sockaddr_in sin{};
        sin.sin_family = AF_INET;
        socklen_t len = sizeof(sin);

        // 127.0.0.1
        inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
        sin.sin_port = htons(80);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 127.0.0.1");

        // 127.0.0.1:8080 rejected even if allow_loopback is true
        sin.sin_port = htons(8080);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, true),
                    "SSRF rejects gateway listening port 127.0.0.1:8080 even in test mode");

        // 0.0.0.0
        inet_pton(AF_INET, "0.0.0.0", &sin.sin_addr);
        sin.sin_port = htons(80);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 0.0.0.0");

        // 10.0.0.1
        inet_pton(AF_INET, "10.0.0.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 10.0.0.1 (private range 10.0.0.0/8)");

        // 172.16.0.1
        inet_pton(AF_INET, "172.16.0.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 172.16.0.1 (private range 172.16.0.0/12)");

        // 172.31.255.255
        inet_pton(AF_INET, "172.31.255.255", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 172.31.255.255 (private range 172.16.0.0/12)");

        // 172.32.0.1 (public)
        inet_pton(AF_INET, "172.32.0.1", &sin.sin_addr);
        assert_test(HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF allows 172.32.0.1 (public IP outside 172.16.0.0/12)");

        // 192.168.1.1
        inet_pton(AF_INET, "192.168.1.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 192.168.1.1 (private range 192.168.0.0/16)");

        // 169.254.1.1
        inet_pton(AF_INET, "169.254.1.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 169.254.1.1 (link-local 169.254.0.0/16)");

        // 100.64.0.1 (CGNAT)
        inet_pton(AF_INET, "100.64.0.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 100.64.0.1 (CGNAT 100.64.0.0/10)");

        // 100.127.255.254 (CGNAT)
        inet_pton(AF_INET, "100.127.255.254", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 100.127.255.254 (CGNAT 100.64.0.0/10)");

        // 192.0.0.1
        inet_pton(AF_INET, "192.0.0.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 192.0.0.1 (IETF 192.0.0.0/24)");

        // 198.18.0.1
        inet_pton(AF_INET, "198.18.0.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 198.18.0.1 (Benchmark 198.18.0.0/15)");

        // 198.19.255.254
        inet_pton(AF_INET, "198.19.255.254", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 198.19.255.254 (Benchmark 198.18.0.0/15)");

        // 240.0.0.1 (Class E reserved)
        inet_pton(AF_INET, "240.0.0.1", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 240.0.0.1 (Reserved 240.0.0.0/4)");

        // 255.255.255.255 (Broadcast)
        inet_pton(AF_INET, "255.255.255.255", &sin.sin_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF rejects 255.255.255.255 (Broadcast)");

        // 8.8.8.8 (public)
        inet_pton(AF_INET, "8.8.8.8", &sin.sin_addr);
        assert_test(HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF allows 8.8.8.8 (public IP)");

        // 93.184.216.34 (example.com)
        inet_pton(AF_INET, "93.184.216.34", &sin.sin_addr);
        assert_test(HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin), len, false),
                    "SSRF allows 93.184.216.34 (public IP)");
    }

    // Test 2: SSRF IPv6 unit validations
    {
        struct sockaddr_in6 sin6{};
        sin6.sin6_family = AF_INET6;
        socklen_t len = sizeof(sin6);

        // ::1
        inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
        sin6.sin6_port = htons(80);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects IPv6 ::1");

        // ::
        inet_pton(AF_INET6, "::", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects IPv6 :: (unspecified)");

        // fe80::1 (link-local)
        inet_pton(AF_INET6, "fe80::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects fe80::1 (IPv6 link-local fe80::/10)");

        // fec0::1 (site-local)
        inet_pton(AF_INET6, "fec0::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects fec0::1 (IPv6 site-local fec0::/10)");

        // fc00::1 (unique local)
        inet_pton(AF_INET6, "fc00::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects fc00::1 (IPv6 unique local fc00::/7)");

        // fd12:3456::1 (unique local)
        inet_pton(AF_INET6, "fd12:3456::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects fd12:3456::1 (IPv6 unique local fc00::/7)");

        // 64:ff9b::1 (IPv4/IPv6 translation prefix)
        inet_pton(AF_INET6, "64:ff9b::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects 64:ff9b::1 (IPv4/IPv6 translation 64:ff9b::/96)");

        // 64:ff9b::192.168.1.1 (translation prefix embedding private IPv4)
        inet_pton(AF_INET6, "64:ff9b::192.168.1.1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects 64:ff9b::192.168.1.1 (embedded private IPv4)");

        // 2002::1 (6to4)
        inet_pton(AF_INET6, "2002::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects 2002::1 (6to4 2002::/16)");

        // 2002:7f00:0001:: (6to4 embedding 127.0.0.1)
        inet_pton(AF_INET6, "2002:7f00:0001::", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects 2002:7f00:0001:: (6to4 embedding loopback)");

        // 2001::1 (Teredo)
        inet_pton(AF_INET6, "2001::1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects 2001::1 (Teredo 2001::/32)");

        // ::ffff:127.0.0.1 (IPv4-mapped loopback)
        inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects IPv4-mapped loopback ::ffff:127.0.0.1");

        // ::ffff:10.0.0.1 (IPv4-mapped private)
        inet_pton(AF_INET6, "::ffff:10.0.0.1", &sin6.sin6_addr);
        assert_test(!HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF rejects IPv4-mapped private ::ffff:10.0.0.1");

        // 2606:2800:220:1:248:1893:25c8:1946 (example.com public IPv6)
        inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", &sin6.sin6_addr);
        assert_test(HttpForwarder::is_ssrf_safe(reinterpret_cast<struct sockaddr*>(&sin6), len, false),
                    "SSRF allows public IPv6 address");
    }

    // Test 3: Rebuild request format tests
    {
        std::string raw =
            "GET http://example.com/index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: curl/7.81.0\r\n"
            "Proxy-Authorization: Basic cGFsYWs6c2VjdXJlcHJveHk=\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        std::string rebuilt = HttpForwarder::rebuild_request(req, "");

        assert_test(rebuilt.find("GET /index.html HTTP/1.1\r\n") == 0,
                    "Rebuilt request starts with origin-form request line");
        assert_test(rebuilt.find("Host: example.com\r\n") != std::string::npos,
                    "Rebuilt request includes canonical Host header for port 80");
        assert_test(rebuilt.find("Proxy-Authorization") == std::string::npos,
                    "Rebuilt request strips Proxy-Authorization");
        assert_test(rebuilt.find("Proxy-Connection") == std::string::npos,
                    "Rebuilt request strips Proxy-Connection");
        assert_test(rebuilt.find("Connection: close\r\n") != std::string::npos,
                    "Rebuilt request forces Connection: close");
        assert_test(rebuilt.find("User-Agent: curl/7.81.0\r\n") != std::string::npos,
                    "Rebuilt request preserves User-Agent header");
    }

    // Test 4: Rebuild request with non-default port and IPv6
    {
        std::string raw1 =
            "GET http://example.com:8080/api HTTP/1.1\r\n"
            "Host: example.com:8080\r\n"
            "\r\n";
        HttpRequest req1 = HttpParser::parse(raw1);
        std::string rebuilt1 = HttpForwarder::rebuild_request(req1, "");
        assert_test(rebuilt1.find("Host: example.com:8080\r\n") != std::string::npos,
                    "Rebuilt request formats non-default port in Host header");

        std::string raw2 =
            "GET http://[::1]:8443/test HTTP/1.1\r\n"
            "Host: [::1]:8443\r\n"
            "\r\n";
        HttpRequest req2 = HttpParser::parse(raw2);
        std::string rebuilt2 = HttpForwarder::rebuild_request(req2, "");
        assert_test(rebuilt2.find("Host: [::1]:8443\r\n") != std::string::npos,
                    "Rebuilt request formats IPv6 with brackets and port in Host header");
    }

    // Test 5: Rebuild request with body and Content-Length
    {
        std::string raw =
            "POST http://example.com/api/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 12\r\n"
            "\r\n"
            "Hello World!";
        HttpRequest req = HttpParser::parse(raw);
        std::string body = raw.substr(req.header_length);
        std::string rebuilt = HttpForwarder::rebuild_request(req, body);

        assert_test(rebuilt.find("POST /api/data HTTP/1.1\r\n") == 0,
                    "Rebuilt POST request line is in origin-form");
        assert_test(rebuilt.find("Content-Length: 12\r\n") != std::string::npos,
                    "Rebuilt POST includes Content-Length matching body");
        assert_test(rebuilt.size() >= 12 && rebuilt.substr(rebuilt.size() - 12) == "Hello World!",
                    "Rebuilt POST request appends full body payload");
    }

    // Test 6: SSRF integration rejection for 127.0.0.1 and localhost
    {
        HttpForwarder forwarder(false); // Default strict SSRF protection

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw1 =
            "GET http://127.0.0.1:8080/admin HTTP/1.1\r\n"
            "Host: 127.0.0.1:8080\r\n"
            "\r\n";
        HttpRequest req1 = HttpParser::parse(raw1);

        ForwardResult res1 = forwarder.forward(req1, "", client_pair[0]);
        assert_test(res1 == ForwardResult::SsrfBlocked, "Forwarder rejects 127.0.0.1 with SsrfBlocked");

        close(client_pair[0]);
        std::string client_resp1 = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp1.find("HTTP/1.1 403 Forbidden") != std::string::npos,
                    "Client receives 403 Forbidden response on SSRF block (127.0.0.1)");

        // Test localhost
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);
        std::string raw2 =
            "GET http://localhost/ HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n";
        HttpRequest req2 = HttpParser::parse(raw2);

        ForwardResult res2 = forwarder.forward(req2, "", client_pair[0]);
        assert_test(res2 == ForwardResult::SsrfBlocked, "Forwarder rejects localhost with SsrfBlocked");

        close(client_pair[0]);
        std::string client_resp2 = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp2.find("HTTP/1.1 403 Forbidden") != std::string::npos,
                    "Client receives 403 Forbidden response on SSRF block (localhost)");
    }

    // Test 7: DNS resolution failure returns 502 Bad Gateway
    {
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET http://definitely-nonexistent-domain-xyz12345.invalid/ HTTP/1.1\r\n"
            "Host: definitely-nonexistent-domain-xyz12345.invalid\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        assert_test(res == ForwardResult::DnsFailure, "DNS resolution failure returns DnsFailure");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("HTTP/1.1 502 Bad Gateway") != std::string::npos,
                    "Client receives 502 Bad Gateway response on DNS failure");
    }

    // Test 8: Connection failure returns 502 Bad Gateway
    {
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        // Pick an unused port on 127.0.0.1 where nothing is listening (e.g. port 1)
        std::string raw =
            "GET http://127.0.0.1:1/ HTTP/1.1\r\n"
            "Host: 127.0.0.1:1\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        assert_test(res == ForwardResult::ConnectFailure, "Connect to closed port returns ConnectFailure");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("HTTP/1.1 502 Bad Gateway") != std::string::npos,
                    "Client receives 502 Bad Gateway response on connection failure");
    }

    // Test 9: Authenticated HTTP GET forwarding to mock destination server
    {
        std::string received_at_destination;
        MockHttpServer server([&received_at_destination](int cfd) {
            char buf[4096];
            ssize_t n = recv(cfd, buf, sizeof(buf), 0);
            if (n > 0) {
                received_at_destination.assign(buf, static_cast<size_t>(n));
            }
            std::string resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 17\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Hello Destination";
            send(cfd, resp.data(), resp.size(), 0);
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true); // allow loopback for test destination

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET http://127.0.0.1:" + std::to_string(srv_port) + "/api/resource?query=1 HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "User-Agent: SecureClient/1.0\r\n"
            "Proxy-Authorization: Basic cGFsYWs6c2VjdXJlcHJveHk=\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n";

        HttpRequest req = HttpParser::parse(raw);

        // Authenticate client request
        Authenticator auth;
        assert_test(auth.authenticate(req.proxy_authorization), "Request is authenticated");

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        assert_test(res == ForwardResult::Success, "Forwarding succeeds with Success");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        // Verify destination received rebuilt request
        assert_test(received_at_destination.find("GET /api/resource?query=1 HTTP/1.1\r\n") == 0,
                    "Destination received origin-form GET request line");
        assert_test(received_at_destination.find("Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n") != std::string::npos,
                    "Destination received canonical Host header with port");
        assert_test(received_at_destination.find("Proxy-Authorization") == std::string::npos,
                    "Destination did NOT receive Proxy-Authorization header");
        assert_test(received_at_destination.find("Proxy-Connection") == std::string::npos,
                    "Destination did NOT receive Proxy-Connection header");
        assert_test(received_at_destination.find("User-Agent: SecureClient/1.0\r\n") != std::string::npos,
                    "Destination received preserved User-Agent header");
        assert_test(received_at_destination.find("Connection: close\r\n") != std::string::npos,
                    "Destination received Connection: close");

        // Verify client received destination response
        assert_test(client_resp.find("HTTP/1.1 200 OK") != std::string::npos,
                    "Client received HTTP/1.1 200 OK status");
        assert_test(client_resp.find("Hello Destination") != std::string::npos,
                    "Client received destination body payload");
    }

    // Test 10: Unauthenticated request gets 407 (Authenticator regression)
    {
        Authenticator auth;
        assert_test(!auth.authenticate(""), "Unauthenticated request without Proxy-Authorization fails authentication");
        assert_test(!auth.authenticate("Basic aW52YWxpZDpwYXNz"), "Invalid credentials fail authentication");
        std::string resp_407 = Authenticator::make_407_response();
        assert_test(resp_407.find("HTTP/1.1 407 Proxy Authentication Required") != std::string::npos,
                    "407 response contains expected status line");
    }

    // Test 11: Large response streaming without memory buffering
    {
        // 256 KB response body
        const size_t large_size = 256 * 1024;
        std::string large_body(large_size, 'X');

        MockHttpServer server([large_size, &large_body](int cfd) {
            char buf[1024];
            recv(cfd, buf, sizeof(buf), 0);
            std::string header =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Content-Length: " + std::to_string(large_size) + "\r\n"
                "Connection: close\r\n"
                "\r\n";
            send(cfd, header.data(), header.size(), 0);

            // Send body in 4 KB chunks
            size_t sent = 0;
            while (sent < large_size) {
                size_t chunk_len = std::min(size_t(4096), large_size - sent);
                send(cfd, large_body.data() + sent, chunk_len, 0);
                sent += chunk_len;
            }
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET http://127.0.0.1:" + std::to_string(srv_port) + "/large HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        // Run reader in background thread so client_pair socket buffer doesn't fill up
        std::string client_resp;
        std::thread reader([client_fd = client_pair[1], &client_resp]() {
            client_resp = read_all_from_socket(client_fd);
            close(client_fd);
        });

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        close(client_pair[0]);

        if (reader.joinable()) {
            reader.join();
        }

        assert_test(res == ForwardResult::Success, "Large response forwarder returns Success");
        assert_test(client_resp.find("HTTP/1.1 200 OK") != std::string::npos,
                    "Client received 200 OK for large response");
        size_t header_sep = client_resp.find("\r\n\r\n");
        assert_test(header_sep != std::string::npos, "Client response has header terminator");
        std::string body_received = client_resp.substr(header_sep + 4);
        assert_test(body_received.size() == large_size,
                    "Client received full streamed 256 KB response body",
                    "Got size: " + std::to_string(body_received.size()));
        assert_test(body_received == large_body, "Client received accurate streamed payload");
    }

    // Test 12: Request body forwarding (POST with Content-Length)
    {
        std::string received_body;
        MockHttpServer server([&received_body](int cfd) {
            char buf[4096];
            ssize_t n = recv(cfd, buf, sizeof(buf), 0);
            if (n > 0) {
                std::string full(buf, static_cast<size_t>(n));
                size_t sep = full.find("\r\n\r\n");
                if (sep != std::string::npos) {
                    received_body = full.substr(sep + 4);
                }
            }
            std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(cfd, resp.data(), resp.size(), 0);
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string payload = "key1=value1&key2=value2";
        std::string raw =
            "POST http://127.0.0.1:" + std::to_string(srv_port) + "/submit HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "Content-Length: " + std::to_string(payload.size()) + "\r\n"
            "\r\n" + payload;
        HttpRequest req = HttpParser::parse(raw);
        std::string initial_body = raw.substr(req.header_length);

        ForwardResult res = forwarder.forward(req, initial_body, client_pair[0]);
        assert_test(res == ForwardResult::Success, "POST with body forwarding succeeds");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(received_body == payload, "Destination received complete request body", "Got: " + received_body);
        assert_test(client_resp.find("HTTP/1.1 200 OK") != std::string::npos, "Client received 200 OK for POST");
    }

    // Test 13: Incomplete request body rejected with 400 Bad Request
    {
        std::atomic<bool> destination_connected{false};
        MockHttpServer server([&destination_connected](int) {
            destination_connected = true;
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        // Header claims Content-Length: 100, but only 10 bytes provided
        std::string raw =
            "POST http://127.0.0.1:" + std::to_string(srv_port) + "/submit HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "Content-Length: 100\r\n"
            "\r\n"
            "0123456789";
        HttpRequest req = HttpParser::parse(raw);
        std::string initial_body = raw.substr(req.header_length);

        // Shut down writing on client_pair[1] to simulate client abort (sending EOF) before sending remaining 90 bytes
        shutdown(client_pair[1], SHUT_WR);

        ForwardResult res = forwarder.forward(req, initial_body, client_pair[0]);
        assert_test(res == ForwardResult::IncompleteRequestBody,
                    "Incomplete request body returns IncompleteRequestBody");
        assert_test(!destination_connected,
                    "Destination server was NOT connected to when request body was incomplete");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);
        assert_test(client_resp.find("HTTP/1.1 400 Bad Request") != std::string::npos,
                    "Client received 400 Bad Request on incomplete body");
    }

    // Test 14: Partial send/recv operations handled cleanly
    {
        MockHttpServer server([](int cfd) {
            char buf[1024];
            recv(cfd, buf, sizeof(buf), 0);
            std::string part1 = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
            std::string part2 = "Content-Length: 11\r\nConnection: close\r\n\r\n";
            std::string part3 = "ChunkedData";
            send(cfd, part1.data(), part1.size(), 0);
            usleep(20000); // 20ms pause
            send(cfd, part2.data(), part2.size(), 0);
            usleep(20000); // 20ms pause
            send(cfd, part3.data(), part3.size(), 0);
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET http://127.0.0.1:" + std::to_string(srv_port) + "/partial HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        assert_test(res == ForwardResult::Success, "Partial packets forwarder returns Success");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("ChunkedData") != std::string::npos,
                    "Client reconstructed full payload across partial packets");
    }

    // Test 15: Response helpers produce valid HTTP responses
    {
        std::string resp_403 = HttpForwarder::make_403_response();
        assert_test(resp_403.find("HTTP/1.1 403 Forbidden") != std::string::npos, "make_403 status line");
        assert_test(resp_403.find("Content-Length: 10") != std::string::npos, "make_403 Content-Length matches");
        assert_test(resp_403.find("Connection: close") != std::string::npos, "make_403 Connection: close");

        std::string resp_413 = HttpForwarder::make_413_response();
        assert_test(resp_413.find("HTTP/1.1 413 Payload Too Large") != std::string::npos, "make_413 status line");
        assert_test(resp_413.find("Content-Length: 18") != std::string::npos, "make_413 Content-Length matches");
        assert_test(resp_413.find("Connection: close") != std::string::npos, "make_413 Connection: close");

        std::string resp_501 = HttpForwarder::make_501_https_response();
        assert_test(resp_501.find("HTTP/1.1 501 Not Implemented") != std::string::npos, "make_501 status line");
        assert_test(resp_501.find("HTTPS proxying requires CONNECT tunneling") != std::string::npos, "make_501 body matches");

        std::string resp_502 = HttpForwarder::make_502_response();
        assert_test(resp_502.find("HTTP/1.1 502 Bad Gateway") != std::string::npos, "make_502 status line");
        assert_test(resp_502.find("Content-Length: 12") != std::string::npos, "make_502 Content-Length matches");
        assert_test(resp_502.find("Connection: close") != std::string::npos, "make_502 Connection: close");

        std::string resp_504 = HttpForwarder::make_504_response();
        assert_test(resp_504.find("HTTP/1.1 504 Gateway Timeout") != std::string::npos, "make_504 status line");
        assert_test(resp_504.find("Content-Length: 16") != std::string::npos, "make_504 Content-Length matches");
        assert_test(resp_504.find("Connection: close") != std::string::npos, "make_504 Connection: close");
    }

    // Test 16: Request body size limit (> 10 MB returns 413, no destination connection)
    {
        std::atomic<bool> destination_connected{false};
        MockHttpServer server([&destination_connected](int) {
            destination_connected = true;
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        // Content-Length exceeds MAX_BODY_BYTES (10 MB + 1 byte)
        size_t oversized = HttpForwarder::MAX_BODY_BYTES + 1;
        std::string raw =
            "POST http://127.0.0.1:" + std::to_string(srv_port) + "/upload HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "Content-Length: " + std::to_string(oversized) + "\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        assert_test(res == ForwardResult::PayloadTooLarge, "Body > 10 MB returns PayloadTooLarge");
        assert_test(!destination_connected, "Destination is NOT connected when body exceeds 10 MB limit");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("HTTP/1.1 413 Payload Too Large") != std::string::npos,
                    "Client receives 413 Payload Too Large");
        assert_test(client_resp.find("Content-Length: 18") != std::string::npos,
                    "413 response includes correct Content-Length");
    }

    // Test 17: Reject HTTPS absolute-form forwarding with 501 Not Implemented
    {
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET https://example.com/secure/page HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        ForwardResult res = forwarder.forward(req, "", client_pair[0]);
        assert_test(res == ForwardResult::NotImplemented,
                    "HTTPS absolute-form target returns NotImplemented");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("HTTP/1.1 501 Not Implemented") != std::string::npos,
                    "Client receives 501 Not Implemented on HTTPS absolute URI");
        assert_test(client_resp.find("HTTPS proxying requires CONNECT tunneling") != std::string::npos,
                    "501 response body explains CONNECT tunneling is required");
    }

    // Test 18: Response timeout before any bytes received -> 504 Gateway Timeout
    {
        MockHttpServer server([](int cfd) {
            // Sleep without sending any response data
            usleep(400000); // 400ms
            (void)cfd;
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET http://127.0.0.1:" + std::to_string(srv_port) + "/slow HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        // Use a short deadline (100ms) for fast and deterministic unit testing
        auto test_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        ForwardResult res = forwarder.forward(req, "", client_pair[0], test_deadline);
        assert_test(res == ForwardResult::Timeout, "Response timeout before any bytes returns Timeout");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("HTTP/1.1 504 Gateway Timeout") != std::string::npos,
                    "Client receives 504 Gateway Timeout when destination times out before response bytes");
        assert_test(client_resp.find("Gateway Timeout\n") != std::string::npos,
                    "504 response body matches Gateway Timeout");
    }

    // Test 19: Response timeout after partial bytes -> connection closes without injecting 504
    {
        MockHttpServer server([](int cfd) {
            std::string partial_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
            send(cfd, partial_resp.data(), partial_resp.size(), 0);
            // Sleep without finishing response
            usleep(400000); // 400ms
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "GET http://127.0.0.1:" + std::to_string(srv_port) + "/partial-stall HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        auto test_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        ForwardResult res = forwarder.forward(req, "", client_pair[0], test_deadline);
        assert_test(res == ForwardResult::Timeout, "Response timeout after partial bytes returns Timeout");

        close(client_pair[0]);
        std::string client_resp = read_all_from_socket(client_pair[1]);
        close(client_pair[1]);

        assert_test(client_resp.find("HTTP/1.1 200 OK") != std::string::npos,
                    "Client received initial 200 OK headers");
        assert_test(client_resp.find("504 Gateway Timeout") == std::string::npos,
                    "504 response is NOT injected after partial response bytes forwarded");
    }

    // Test 20: Slow-drip request body terminated when forwarding deadline expires
    {
        std::atomic<bool> destination_connected{false};
        MockHttpServer server([&destination_connected](int) {
            destination_connected = true;
        });

        uint16_t srv_port = server.port();
        HttpForwarder forwarder(true);

        int client_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) == 0);

        std::string raw =
            "POST http://127.0.0.1:" + std::to_string(srv_port) + "/slow-upload HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(srv_port) + "\r\n"
            "Content-Length: 50\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);

        // Dripper thread sending 1 byte every 40ms
        std::atomic<bool> stop_dripper{false};
        std::thread dripper([cfd = client_pair[1], &stop_dripper]() {
            for (int i = 0; i < 20 && !stop_dripper; ++i) {
                char byte = 'A';
                ssize_t s = send(cfd, &byte, 1, MSG_NOSIGNAL);
                if (s <= 0) break;
                usleep(40000); // 40ms
            }
        });

        // Forwarder deadline set to 100ms
        auto test_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        ForwardResult res = forwarder.forward(req, "", client_pair[0], test_deadline);
        assert_test(res == ForwardResult::IncompleteRequestBody,
                    "Slow-drip body terminates with IncompleteRequestBody upon deadline expiry");
        assert_test(!destination_connected,
                    "Destination is NOT connected when slow-drip body times out");

        stop_dripper = true;
        close(client_pair[0]);
        if (dripper.joinable()) {
            dripper.join();
        }
        close(client_pair[1]);
    }

    std::cout << "\nTest Results: " << g_passed << " passed, " << g_failed << " failed." << std::endl;
    return g_failed == 0 ? 0 : 1;
}
