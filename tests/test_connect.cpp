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
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

namespace {

bool create_tcp_loopback_pair(int& local_fd, int& peer_fd) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return false;

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0) {
        close(listen_fd);
        return false;
    }
    if (listen(listen_fd, 1) < 0) {
        close(listen_fd);
        return false;
    }

    socklen_t len = sizeof(sin);
    if (getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&sin), &len) < 0) {
        close(listen_fd);
        return false;
    }

    peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd < 0) {
        close(listen_fd);
        return false;
    }

    if (connect(peer_fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0) {
        close(listen_fd);
        close(peer_fd);
        return false;
    }

    local_fd = accept(listen_fd, nullptr, nullptr);
    close(listen_fd);
    if (local_fd < 0) {
        close(peer_fd);
        return false;
    }
    return true;
}

std::atomic<int> g_passed{0};
std::atomic<int> g_failed{0};

void verify_ok(bool condition, const std::string& msg = "") {
    if (!condition) {
        std::cerr << "Verification failed: " << msg << std::endl;
        std::abort();
    }
}

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
class MockConnectServer {
public:
    explicit MockConnectServer(std::function<void(int client_fd)> handler)
        : handler_(std::move(handler)) {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0) {
            perror("MockConnectServer bind failed");
        }
        if (listen(server_fd_, 5) < 0) {
            perror("MockConnectServer listen failed");
        }

        socklen_t len = sizeof(sin);
        getsockname(server_fd_, reinterpret_cast<struct sockaddr*>(&sin), &len);
        port_ = ntohs(sin.sin_port);

        worker_ = std::thread([this]() {
            while (running_) {
                struct pollfd pfd{};
                pfd.fd = server_fd_;
                pfd.events = POLLIN;
                int r = poll(&pfd, 1, 50);
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

    ~MockConnectServer() {
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

std::string read_bytes_with_timeout(int fd, size_t count, int timeout_ms = 2000) {
    std::string out;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (out.size() < count) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int r = poll(&pfd, 1, static_cast<int>(rem));
        if (r <= 0) {
            break;
        }
        char buf[512];
        size_t needed = std::min(sizeof(buf), count - out.size());
        ssize_t n = recv(fd, buf, needed, 0);
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
    std::cout << "Running CONNECT Tunneling Test Suite..." << std::endl;

    // Test 1: Unauthenticated CONNECT is rejected with 407
    {
        std::string raw =
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "CONNECT request parsed successfully");
        assert_test(req.method == "CONNECT", "Method is CONNECT");

        Authenticator auth;
        assert_test(!auth.authenticate(req.proxy_authorization),
                    "Missing Proxy-Authorization fails authentication");

        std::string resp_407 = Authenticator::make_407_response();
        assert_test(resp_407.find("HTTP/1.1 407 Proxy Authentication Required\r\n") != std::string::npos,
                    "407 response contains expected status line");
        assert_test(resp_407.find("Proxy-Authenticate: Basic realm=\"SecureProxyGateway\"\r\n") != std::string::npos,
                    "407 response contains Proxy-Authenticate header with realm");
        assert_test(resp_407.find("Connection: close\r\n") != std::string::npos,
                    "407 response contains Connection: close");
    }

    // Test 2: Invalid credentials on CONNECT are rejected with 407
    {
        std::string raw =
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "Proxy-Authorization: Basic aW52YWxpZDpiYWQ=\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        Authenticator auth;
        assert_test(!auth.authenticate(req.proxy_authorization),
                    "Invalid credentials on CONNECT fail authentication");
    }

    // Test 3: Malformed CONNECT targets are rejected (400 Bad Request)
    {
        // Missing port
        std::string raw_no_port = "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        HttpRequest req_no_port = HttpParser::parse(raw_no_port);
        assert_test(!req_no_port.valid && req_no_port.is_error(), "Reject CONNECT without port");

        // Invalid non-numeric port
        std::string raw_bad_port = "CONNECT example.com:abc HTTP/1.1\r\nHost: example.com:abc\r\n\r\n";
        HttpRequest req_bad_port = HttpParser::parse(raw_bad_port);
        assert_test(!req_bad_port.valid && req_bad_port.is_error(), "Reject CONNECT with non-numeric port");

        // Port 0
        std::string raw_port_0 = "CONNECT example.com:0 HTTP/1.1\r\nHost: example.com:0\r\n\r\n";
        HttpRequest req_port_0 = HttpParser::parse(raw_port_0);
        assert_test(!req_port_0.valid && req_port_0.is_error(), "Reject CONNECT with port 0");

        // Userinfo in target
        std::string raw_user = "CONNECT user@example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        HttpRequest req_user = HttpParser::parse(raw_user);
        assert_test(!req_user.valid && req_user.is_error(), "Reject CONNECT with userinfo");

        // Path in target
        std::string raw_path = "CONNECT example.com:443/path HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        HttpRequest req_path = HttpParser::parse(raw_path);
        assert_test(!req_path.valid && req_path.is_error(), "Reject CONNECT with path in target");

        // Query in target
        std::string raw_query = "CONNECT example.com:443?query=1 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        HttpRequest req_query = HttpParser::parse(raw_query);
        assert_test(!req_query.valid && req_query.is_error(), "Reject CONNECT with query in target");

        std::string resp_400 = HttpParser::make_400_response();
        assert_test(resp_400.find("HTTP/1.1 400 Bad Request\r\n") != std::string::npos,
                    "Malformed request generates 400 Bad Request");
    }

    // Test 4: SSRF protection blocks private / loopback CONNECT targets
    {
        HttpForwarder forwarder(false); // Strict production SSRF enforcement

        // 127.0.0.1
        {
            int p[2];
            verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
            std::string raw = "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n";
            HttpRequest req = HttpParser::parse(raw);
            ForwardResult res = forwarder.forward_connect(req, "", p[0]);
            assert_test(res == ForwardResult::SsrfBlocked, "CONNECT to 127.0.0.1 blocked by SSRF");
            close(p[0]);
            std::string resp = read_all_from_socket(p[1]);
            close(p[1]);
            assert_test(resp.find("HTTP/1.1 403 Forbidden\r\n") != std::string::npos,
                        "SSRF block returns 403 Forbidden for 127.0.0.1");
        }

        // localhost
        {
            int p[2];
            verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
            std::string raw = "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
            HttpRequest req = HttpParser::parse(raw);
            ForwardResult res = forwarder.forward_connect(req, "", p[0]);
            assert_test(res == ForwardResult::SsrfBlocked, "CONNECT to localhost blocked by SSRF");
            close(p[0]);
            std::string resp = read_all_from_socket(p[1]);
            close(p[1]);
            assert_test(resp.find("HTTP/1.1 403 Forbidden\r\n") != std::string::npos,
                        "SSRF block returns 403 Forbidden for localhost");
        }

        // Private IPv4 (10.0.0.1)
        {
            int p[2];
            verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
            std::string raw = "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n";
            HttpRequest req = HttpParser::parse(raw);
            ForwardResult res = forwarder.forward_connect(req, "", p[0]);
            assert_test(res == ForwardResult::SsrfBlocked, "CONNECT to 10.0.0.1 blocked by SSRF");
            close(p[0]);
            std::string resp = read_all_from_socket(p[1]);
            close(p[1]);
            assert_test(resp.find("HTTP/1.1 403 Forbidden\r\n") != std::string::npos,
                        "SSRF block returns 403 Forbidden for 10.0.0.1");
        }
    }

    // Test 5: Connect failure to closed port returns 502 Bad Gateway
    {
        HttpForwarder forwarder(true); // Allow loopback for test
        int p[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
        // Connect to an unused port
        std::string raw = "CONNECT 127.0.0.1:59999 HTTP/1.1\r\nHost: 127.0.0.1:59999\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        ForwardResult res = forwarder.forward_connect(req, "", p[0]);
        assert_test(res == ForwardResult::ConnectFailure, "Connect to closed port returns ConnectFailure");
        close(p[0]);
        std::string resp = read_all_from_socket(p[1]);
        close(p[1]);
        assert_test(resp.find("HTTP/1.1 502 Bad Gateway\r\n") != std::string::npos,
                    "Client receives 502 Bad Gateway on connect failure");
    }

    // Test 6: Successful tunnel establishment with mock destination
    {
        std::atomic<bool> server_connected{false};
        MockConnectServer mock([&server_connected](int client_fd) {
            server_connected = true;
            char buf[64];
            (void)recv(client_fd, buf, sizeof(buf), 0);
        });

        HttpForwarder forwarder(true); // Allow loopback for testing
        int p[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);

        std::string raw = "CONNECT 127.0.0.1:" + std::to_string(mock.port()) + " HTTP/1.1\r\n"
                          "Host: 127.0.0.1:" + std::to_string(mock.port()) + "\r\n"
                          "Proxy-Authorization: Basic cGFsYWs6c2VjdXJlcHJveHk=\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);

        std::thread client_thread([&forwarder, &req, p0 = p[0]]() {
            forwarder.forward_connect(req, "", p0);
            close(p0);
        });

        // Read 200 Connection Established response on client side
        std::string expected_resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        std::string client_received = read_bytes_with_timeout(p[1], expected_resp.size());
        assert_test(client_received == expected_resp,
                    "Client received HTTP/1.1 200 Connection Established");

        // Wait up to 1000ms for mock destination to accept the established connection
        auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
        while (!server_connected && std::chrono::steady_clock::now() < wait_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        // Close client to unblock server and forwarder
        close(p[1]);
        client_thread.join();
        assert_test(server_connected, "Destination server was successfully connected to");
    }

    // Test 7: Bidirectional data transfer through the tunnel
    {
        std::string dest_received_data;
        const std::string client_msg = "TLS_CLIENT_HELLO_SIMULATION_PAYLOAD_1234567890";
        const std::string server_msg = "TLS_SERVER_HELLO_CERTIFICATE_KEY_EXCHANGE_REPLY";

        MockConnectServer mock([&dest_received_data, &client_msg, &server_msg](int client_fd) {
            char buf[256];
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                dest_received_data.assign(buf, static_cast<size_t>(n));
            }
            send(client_fd, server_msg.data(), server_msg.size(), 0);
            shutdown(client_fd, SHUT_WR);
        });

        HttpForwarder forwarder(true);
        int p[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);

        std::string raw = "CONNECT 127.0.0.1:" + std::to_string(mock.port()) + " HTTP/1.1\r\n"
                          "Host: 127.0.0.1:" + std::to_string(mock.port()) + "\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);

        std::thread fwd_thread([&forwarder, &req, p0 = p[0]]() {
            ForwardResult res = forwarder.forward_connect(req, "", p0);
            assert_test(res == ForwardResult::Success, "forward_connect completed with Success");
            close(p0);
        });

        // 1. Read 200 response
        std::string conn_est = read_bytes_with_timeout(p[1], 39);
        assert_test(conn_est == "HTTP/1.1 200 Connection Established\r\n\r\n",
                    "Received 200 Connection Established before relay");

        // 2. Client sends payload to destination
        ssize_t s = send(p[1], client_msg.data(), client_msg.size(), 0);
        assert_test(s == static_cast<ssize_t>(client_msg.size()), "Client sent full payload to destination");

        // 3. Client reads response payload from destination
        std::string server_reply = read_bytes_with_timeout(p[1], server_msg.size());
        assert_test(server_reply == server_msg, "Client received accurate server payload from destination");

        // 4. Shutdown client write and wait for completion
        shutdown(p[1], SHUT_WR);
        close(p[1]);
        fwd_thread.join();

        assert_test(dest_received_data == client_msg, "Destination received accurate client payload");
    }

    // Test 8: Pipelined initial client data forwarded immediately
    {
        std::string dest_received_data;
        const std::string pipelined = "PRE_READ_CLIENT_DATA_IN_FIRST_PACKET";

        MockConnectServer mock([&dest_received_data](int client_fd) {
            char buf[256];
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                dest_received_data.assign(buf, static_cast<size_t>(n));
            }
        });

        HttpForwarder forwarder(true);
        int p[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);

        std::string raw = "CONNECT 127.0.0.1:" + std::to_string(mock.port()) + " HTTP/1.1\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);

        std::thread fwd_thread([&forwarder, &req, &pipelined, p0 = p[0]]() {
            forwarder.forward_connect(req, pipelined, p0);
            close(p0);
        });

        std::string conn_est = read_bytes_with_timeout(p[1], 39);
        assert_test(conn_est.find("200 Connection Established") != std::string::npos,
                    "Client received 200 for pipelined request");

        close(p[1]);
        fwd_thread.join();

        assert_test(dest_received_data == pipelined,
                    "Pipelined initial client data was forwarded to destination upon 200");
    }

    // Test 9: Direct relay_tunnel bidirectional test via socketpairs
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        const std::string msg_to_dest = "HELLO_DESTINATION";
        const std::string msg_to_client = "HELLO_CLIENT";

        std::thread relay_thread([c0 = client_side[0], d0 = dest_side[0]]() {
            ForwardResult r = HttpForwarder::relay_tunnel(c0, d0);
            assert_test(r == ForwardResult::Success, "relay_tunnel completed with Success");
            close(c0);
            close(d0);
        });

        // Real client writes to client_side[1]
        send(client_side[1], msg_to_dest.data(), msg_to_dest.size(), 0);

        // Real dest reads from dest_side[1]
        std::string received_at_dest = read_bytes_with_timeout(dest_side[1], msg_to_dest.size());
        assert_test(received_at_dest == msg_to_dest, "relay forwarded client -> dest");

        // Real dest replies
        send(dest_side[1], msg_to_client.data(), msg_to_client.size(), 0);
        shutdown(dest_side[1], SHUT_WR);

        // Real client reads reply
        std::string received_at_client = read_bytes_with_timeout(client_side[1], msg_to_client.size());
        assert_test(received_at_client == msg_to_client, "relay forwarded dest -> client");

        shutdown(client_side[1], SHUT_WR);
        close(client_side[1]);
        close(dest_side[1]);

        relay_thread.join();
    }

    // Test 10: Tunnel closes cleanly on client EOF
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        std::thread relay_thread([c0 = client_side[0], d0 = dest_side[0]]() {
            ForwardResult r = HttpForwarder::relay_tunnel(c0, d0);
            assert_test(r == ForwardResult::Success, "Tunnel terminated successfully on EOF");
            close(c0);
            close(d0);
        });

        // Client immediately sends FIN (EOF)
        shutdown(client_side[1], SHUT_WR);

        // Destination should read EOF (0 bytes)
        char buf[16];
        ssize_t n = recv(dest_side[1], buf, sizeof(buf), 0);
        assert_test(n == 0, "Destination observed EOF when client sent FIN");

        // Destination sends FIN (EOF)
        shutdown(dest_side[1], SHUT_WR);
        close(client_side[1]);
        close(dest_side[1]);

        relay_thread.join();
    }

    // Test 11: Idle timeout behavior
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        auto t0 = std::chrono::steady_clock::now();
        ForwardResult r = HttpForwarder::relay_tunnel(
            client_side[0], dest_side[0],
            "",
            std::chrono::milliseconds(150), // idle timeout 150ms
            std::chrono::seconds(10)        // total timeout 10s
        );
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

        assert_test(r == ForwardResult::Timeout, "relay_tunnel returns Timeout when idle");
        assert_test(elapsed >= 140 && elapsed < 1000, "Idle timeout fired within expected window", "Elapsed ms: " + std::to_string(elapsed));

        // Confirm no HTTP error text was sent to either socket
        char buf[32];
        ssize_t c_bytes = recv(client_side[1], buf, sizeof(buf), MSG_DONTWAIT);
        ssize_t d_bytes = recv(dest_side[1], buf, sizeof(buf), MSG_DONTWAIT);
        assert_test(c_bytes <= 0 && d_bytes <= 0, "No HTTP error was injected on idle timeout");

        close(client_side[0]);
        close(client_side[1]);
        close(dest_side[0]);
        close(dest_side[1]);
    }

    // Test 12: Idle timeout resets upon active traffic
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        std::atomic<bool> done{false};
        std::thread traffic_thread([&client_side, &dest_side, &done]() {
            // Send packets at 70ms and 140ms (idle timeout is 120ms)
            std::this_thread::sleep_for(std::chrono::milliseconds(70));
            send(client_side[1], "a", 1, 0);
            char b;
            (void)recv(dest_side[1], &b, 1, 0);

            std::this_thread::sleep_for(std::chrono::milliseconds(70));
            send(dest_side[1], "b", 1, 0);
            (void)recv(client_side[1], &b, 1, 0);

            done = true;
        });

        auto t0 = std::chrono::steady_clock::now();
        ForwardResult r = HttpForwarder::relay_tunnel(
            client_side[0], dest_side[0],
            "",
            std::chrono::milliseconds(120), // idle timeout 120ms
            std::chrono::seconds(5)
        );
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

        traffic_thread.join();
        assert_test(r == ForwardResult::Timeout, "relay_tunnel eventually times out after traffic stops");
        assert_test(elapsed >= 250, "Idle timeout was properly postponed by intermediate traffic", "Elapsed ms: " + std::to_string(elapsed));
        assert_test(done, "Traffic occurred as scheduled");

        close(client_side[0]);
        close(client_side[1]);
        close(dest_side[0]);
        close(dest_side[1]);
    }

    // Test 13: Total timeout lifetime cap
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        std::atomic<bool> keep_sending{true};
        std::thread pumper([&client_side, &keep_sending]() {
            while (keep_sending) {
                send(client_side[1], "x", 1, MSG_NOSIGNAL);
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
            }
        });

        std::thread drainer([&dest_side, &keep_sending]() {
            char buf[64];
            while (keep_sending) {
                (void)recv(dest_side[1], buf, sizeof(buf), MSG_DONTWAIT);
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
            }
        });

        auto t0 = std::chrono::steady_clock::now();
        ForwardResult r = HttpForwarder::relay_tunnel(
            client_side[0], dest_side[0],
            "",
            std::chrono::milliseconds(500), // idle timeout 500ms
            std::chrono::milliseconds(200)  // total timeout 200ms
        );
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

        keep_sending = false;
        pumper.join();
        drainer.join();

        assert_test(r == ForwardResult::Timeout, "relay_tunnel terminates on total timeout cap");
        assert_test(elapsed >= 190 && elapsed < 450, "Total timeout fired near 200ms cap despite constant traffic", "Elapsed ms: " + std::to_string(elapsed));

        close(client_side[0]);
        close(client_side[1]);
        close(dest_side[0]);
        close(dest_side[1]);
    }

    // Test 14: Partial / large payload transmission
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        // 64 KB payload
        std::string large_payload(64 * 1024, 'K');
        for (size_t i = 0; i < large_payload.size(); ++i) {
            large_payload[i] = static_cast<char>('A' + (i % 26));
        }

        std::thread relay_thread([c0 = client_side[0], d0 = dest_side[0]]() {
            ForwardResult r = HttpForwarder::relay_tunnel(c0, d0);
            assert_test(r == ForwardResult::Success, "Large payload relay succeeded");
            close(c0);
            close(d0);
        });

        std::thread sender([&client_side, &large_payload]() {
            size_t sent = 0;
            while (sent < large_payload.size()) {
                ssize_t s = send(client_side[1], large_payload.data() + sent, large_payload.size() - sent, 0);
                if (s > 0) sent += static_cast<size_t>(s);
            }
            shutdown(client_side[1], SHUT_WR);
        });

        std::string dest_received;
        char buf[4096];
        while (dest_received.size() < large_payload.size()) {
            ssize_t n = recv(dest_side[1], buf, sizeof(buf), 0);
            if (n <= 0) break;
            dest_received.append(buf, static_cast<size_t>(n));
        }
        shutdown(dest_side[1], SHUT_WR);

        sender.join();
        close(client_side[1]);
        close(dest_side[1]);
        relay_thread.join();

        assert_test(dest_received == large_payload, "Destination received complete uncorrupted 64 KB payload");
    }

    // Test 15: MUST FIX Regression test for relay_tunnel POLLERR/POLLHUP busy-spin
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        // Shrink socket send/receive buffers so destination buffer fills up quickly
        int buf_size = 4096;
        setsockopt(dest_side[0], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        setsockopt(dest_side[1], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

        std::atomic<ForwardResult> relay_res{ForwardResult::Success};
        std::atomic<bool> thread_done{false};

        std::thread relay_thread([c0 = client_side[0], d0 = dest_side[0], &relay_res, &thread_done]() {
            // Idle timeout 2000ms. Without fix, busy-spins until 2000ms.
            // With fix, exits immediately (<100ms) on POLLHUP when POLLIN not in events mask.
            relay_res = HttpForwarder::relay_tunnel(
                c0, d0, "",
                std::chrono::milliseconds(2000),
                std::chrono::seconds(10)
            );
            thread_done = true;
            close(c0);
            close(d0);
        });

        // Destination side never reads from dest_side[1].
        // Client pushes enough data to saturate destination socket buffer and fill relay c2d_buf (16 KB),
        // causing backpressure so relay removes POLLIN from client_side[0].
        std::string junk(8192, 'Z');
        for (int i = 0; i < 16; ++i) {
            ssize_t s = send(client_side[1], junk.data(), junk.size(), MSG_NOSIGNAL);
            if (s <= 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        // Give relay a moment to read junk into c2d_buf and saturate dest write buffer
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Now close client peer. This sends HUP/ERR to client_side[0] while POLLIN is NOT in events.
        auto close_time = std::chrono::steady_clock::now();
        close(client_side[1]);

        relay_thread.join();
        auto elapsed_after_close = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - close_time).count();

        assert_test(relay_res.load() == ForwardResult::RecvFailure,
                    "Busy-spin regression: relay terminates with RecvFailure on unpolled HUP/ERR");
        assert_test(elapsed_after_close < 600,
                    "Busy-spin regression: relay terminated quickly (<600ms vs 2000ms idle timeout)",
                    "Elapsed ms after close: " + std::to_string(elapsed_after_close));

        close(dest_side[1]);
    }

    // Test 16: CONNECT port restrictions (allow 443 and 8443, reject all others with 403)
    {
        HttpForwarder forwarder(false); // Strict production mode

        int p[2];
        // Port 80
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
        std::string raw80 = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n";
        HttpRequest req80 = HttpParser::parse(raw80);
        ForwardResult res80 = forwarder.forward_connect(req80, "", p[0]);
        assert_test(res80 == ForwardResult::SsrfBlocked, "Reject CONNECT port 80");
        close(p[0]);
        std::string resp80 = read_all_from_socket(p[1]);
        close(p[1]);
        assert_test(resp80.find("HTTP/1.1 403 Forbidden") != std::string::npos, "Port 80 returns 403 Forbidden");

        // Port 8080
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
        std::string raw8080 = "CONNECT example.com:8080 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        HttpRequest req8080 = HttpParser::parse(raw8080);
        ForwardResult res8080 = forwarder.forward_connect(req8080, "", p[0]);
        assert_test(res8080 == ForwardResult::SsrfBlocked, "Reject CONNECT port 8080");
        close(p[0]);
        std::string resp8080 = read_all_from_socket(p[1]);
        close(p[1]);
        assert_test(resp8080.find("HTTP/1.1 403 Forbidden") != std::string::npos, "Port 8080 returns 403 Forbidden");

        // Port 22
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
        std::string raw22 = "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n";
        HttpRequest req22 = HttpParser::parse(raw22);
        ForwardResult res22 = forwarder.forward_connect(req22, "", p[0]);
        assert_test(res22 == ForwardResult::SsrfBlocked, "Reject CONNECT port 22");
        close(p[0]);
        std::string resp22 = read_all_from_socket(p[1]);
        close(p[1]);
        assert_test(resp22.find("HTTP/1.1 403 Forbidden") != std::string::npos, "Port 22 returns 403 Forbidden");

        // Port 443 and 8443 are allowed by is_allowed_connect_port helper
        assert_test(HttpForwarder::is_allowed_connect_port(443), "Port 443 is allowed");
        assert_test(HttpForwarder::is_allowed_connect_port(8443), "Port 8443 is allowed");
        assert_test(!HttpForwarder::is_allowed_connect_port(80), "Port 80 is not allowed");
        assert_test(!HttpForwarder::is_allowed_connect_port(8080), "Port 8080 is not allowed");
    }

    // Test 17: Concurrent tunnel cap and 503 response
    {
        std::string resp_503 = HttpForwarder::make_503_response();
        assert_test(resp_503.find("HTTP/1.1 503 Service Unavailable\r\n") != std::string::npos,
                    "make_503_response returns 503 Service Unavailable");
        assert_test(resp_503.find("Content-Length: 20\r\n") != std::string::npos,
                    "503 response has accurate Content-Length");

        // Temporarily set cap to 1
        HttpForwarder::set_max_concurrent_tunnels(1);
        assert_test(HttpForwarder::try_acquire_tunnel(), "First tunnel acquire succeeds");
        assert_test(!HttpForwarder::try_acquire_tunnel(), "Second tunnel acquire rejected at cap");

        HttpForwarder::release_tunnel();
        assert_test(HttpForwarder::try_acquire_tunnel(), "Tunnel acquire succeeds after release");
        HttpForwarder::release_tunnel();

        // Restore default limit
        HttpForwarder::set_max_concurrent_tunnels(HttpForwarder::DEFAULT_MAX_CONCURRENT_TUNNELS);
        assert_test(HttpForwarder::active_tunnels() == 0, "All test tunnels released cleanly");
    }

    // Test 18: Destination EOF does not lose buffered client data (drains c2d before exit)
    {
        int client_side[2];
        int dest_side[2];
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, client_side) == 0);
        verify_ok(socketpair(AF_UNIX, SOCK_STREAM, 0, dest_side) == 0);

        const std::string pending_client_data = "IMPORTANT_CLIENT_PAYLOAD_MUST_NOT_BE_LOST";

        std::thread relay_thread([c0 = client_side[0], d0 = dest_side[0], &pending_client_data]() {
            ForwardResult r = HttpForwarder::relay_tunnel(
                c0, d0, pending_client_data,
                std::chrono::seconds(2),
                std::chrono::seconds(5)
            );
            assert_test(r == ForwardResult::Success, "Relay succeeded and drained c2d before exit");
            close(c0);
            close(d0);
        });

        // Destination immediately sends EOF (shuts down write side)
        shutdown(dest_side[1], SHUT_WR);

        // Destination reads from dest_side[1]; verify pending_client_data was delivered!
        std::string received_at_dest = read_bytes_with_timeout(dest_side[1], pending_client_data.size());
        assert_test(received_at_dest == pending_client_data,
                    "Destination received buffered client data even though dest sent EOF first");

        // Client closes
        close(client_side[1]);
        close(dest_side[1]);
        relay_thread.join();
    }

    // Test 19: Client-side half-close-then-reset busy-spin regression test
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::Success};
        std::atomic<double> cpu_sec{0.0};
        std::atomic<double> wall_sec{0.0};

        std::thread relay_thread([&]() {
            struct timespec c0, c1, w0, w1;
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);
            clock_gettime(CLOCK_MONOTONIC, &w0);

            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(1500),
                std::chrono::seconds(5)
            );

            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
            clock_gettime(CLOCK_MONOTONIC, &w1);
            cpu_sec = (c1.tv_sec - c0.tv_sec) + (c1.tv_nsec - c0.tv_nsec) / 1e9;
            wall_sec = (w1.tv_sec - w0.tv_sec) + (w1.tv_nsec - w0.tv_nsec) / 1e9;

            close(client_fd);
            close(dest_fd);
        });

        // Client sends FIN (half-close)
        shutdown(client_peer, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Client sends RST (SO_LINGER {1, 0} + close)
        struct linger sl{1, 0};
        setsockopt(client_peer, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        close(client_peer);

        relay_thread.join();
        close(dest_peer);

        ForwardResult res = relay_res.load();
        assert_test(res == ForwardResult::RecvFailure || res == ForwardResult::ClientDisconnect,
                    "Client half-close-then-reset terminates cleanly without timing out");
        assert_test(cpu_sec.load() < 0.05,
                    "Client half-close-then-reset CPU time bounded (<0.05s, no busy-spin)",
                    "CPU sec: " + std::to_string(cpu_sec.load()) + ", Wall sec: " + std::to_string(wall_sec.load()));
    }

    // Test 20: Destination-side clean half-close without reset regression test
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::Success};
        std::atomic<double> cpu_sec{0.0};
        std::atomic<double> wall_sec{0.0};

        std::thread relay_thread([&]() {
            struct timespec c0, c1, w0, w1;
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);
            clock_gettime(CLOCK_MONOTONIC, &w0);

            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(1500),
                std::chrono::seconds(5)
            );

            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
            clock_gettime(CLOCK_MONOTONIC, &w1);
            cpu_sec = (c1.tv_sec - c0.tv_sec) + (c1.tv_nsec - c0.tv_nsec) / 1e9;
            wall_sec = (w1.tv_sec - w0.tv_sec) + (w1.tv_nsec - w0.tv_nsec) / 1e9;

            close(client_fd);
            close(dest_fd);
        });

        // Destination sends FIN (half-close)
        shutdown(dest_peer, SHUT_WR);

        // Client observes forwarded EOF and closes write side (clean two-way half-close)
        char b;
        ssize_t n = recv(client_peer, &b, 1, 0);
        verify_ok(n == 0);
        shutdown(client_peer, SHUT_WR);

        relay_thread.join();
        close(dest_peer);
        close(client_peer);

        assert_test(relay_res.load() == ForwardResult::Success,
                    "Destination half-close completes successfully when client has no pending data");
        assert_test(cpu_sec.load() < 0.05,
                    "Destination half-close CPU time bounded (<0.05s, no busy-spin)",
                    "CPU sec: " + std::to_string(cpu_sec.load()));
    }

    // Test 21: Destination-side unexpected RST while client waiting
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::Success};
        std::atomic<double> cpu_sec{0.0};

        std::thread relay_thread([&]() {
            struct timespec c0, c1;
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);

            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(1500),
                std::chrono::seconds(5)
            );

            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
            cpu_sec = (c1.tv_sec - c0.tv_sec) + (c1.tv_nsec - c0.tv_nsec) / 1e9;

            close(client_fd);
            close(dest_fd);
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        // Destination sends RST directly without clean FIN
        struct linger sl{1, 0};
        setsockopt(dest_peer, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        close(dest_peer);

        relay_thread.join();
        close(client_peer);

        assert_test(relay_res.load() == ForwardResult::RecvFailure,
                    "Destination unexpected RST terminates with RecvFailure");
        assert_test(cpu_sec.load() < 0.05,
                    "Destination unexpected RST CPU time bounded (<0.05s)",
                    "CPU sec: " + std::to_string(cpu_sec.load()));
    }

    // Test 22: Clean client half-close with destination response
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::RecvFailure};

        std::thread relay_thread([&]() {
            relay_res = HttpForwarder::relay_tunnel(client_fd, dest_fd);
            close(client_fd);
            close(dest_fd);
        });

        // Client sends request then sends FIN
        const std::string client_req = "GET / HTTP/1.1\r\n\r\n";
        send(client_peer, client_req.data(), client_req.size(), 0);
        shutdown(client_peer, SHUT_WR);

        // Destination receives request and EOF
        char buf[128];
        ssize_t n = recv(dest_peer, buf, sizeof(buf), 0);
        verify_ok(n == static_cast<ssize_t>(client_req.size()));
        n = recv(dest_peer, buf, sizeof(buf), 0);
        verify_ok(n == 0); // Observed EOF

        // Destination sends response and sends FIN
        const std::string dest_resp = "HTTP/1.1 200 OK\r\n\r\n";
        send(dest_peer, dest_resp.data(), dest_resp.size(), 0);
        shutdown(dest_peer, SHUT_WR);

        // Client receives response and EOF
        n = recv(client_peer, buf, sizeof(buf), 0);
        verify_ok(n == static_cast<ssize_t>(dest_resp.size()));
        n = recv(client_peer, buf, sizeof(buf), 0);
        verify_ok(n == 0);

        close(client_peer);
        close(dest_peer);

        relay_thread.join();
        assert_test(relay_res.load() == ForwardResult::Success,
                    "Clean client half-close with destination response succeeds");
    }

    // Test 23: Half-closed destination response under backpressure drains completely (F1 fix)
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::RecvFailure};

        std::thread relay_thread([&]() {
            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(5000),
                std::chrono::seconds(30)
            );
            close(client_fd);
            close(dest_fd);
        });

        // Client sends short request and half-closes (SHUT_WR)
        const std::string client_req = "GET /large HTTP/1.1\r\n\r\n";
        send(client_peer, client_req.data(), client_req.size(), 0);
        shutdown(client_peer, SHUT_WR);

        // Destination reads the request
        char buf[128];
        ssize_t n = recv(dest_peer, buf, sizeof(buf), 0);
        verify_ok(n == static_cast<ssize_t>(client_req.size()));

        // Destination sends 1 MB response with position-dependent pattern in a separate thread
        constexpr size_t TOTAL_BYTES = 1024 * 1024;
        std::vector<char> big_resp(TOTAL_BYTES);
        for (size_t i = 0; i < TOTAL_BYTES; ++i) {
            big_resp[i] = static_cast<char>('A' + (i % 26));
        }

        std::atomic<size_t> total_sent{0};
        std::thread dest_sender([&]() {
            size_t sent = 0;
            while (sent < TOTAL_BYTES) {
                ssize_t s = send(dest_peer, big_resp.data() + sent, TOTAL_BYTES - sent, 0);
                if (s <= 0) break;
                sent += static_cast<size_t>(s);
            }
            total_sent = sent;
            close(dest_peer);
        });

        // Client reads slowly in 4 KB chunks with short sleeps (causing backpressure on d2c)
        std::vector<char> client_received;
        char chunk[4096];
        while (true) {
            ssize_t r = recv(client_peer, chunk, sizeof(chunk), 0);
            if (r <= 0) break;
            client_received.insert(client_received.end(), chunk, chunk + r);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        close(client_peer);

        dest_sender.join();
        relay_thread.join();

        assert_test(total_sent.load() == TOTAL_BYTES,
                    "Destination successfully sent full 1 MB payload");
        assert_test(client_received == big_resp,
                    "Client received entire 1 MB payload matching pattern under backpressure without truncation",
                    "Received " + std::to_string(client_received.size()) + " / " + std::to_string(TOTAL_BYTES));
        assert_test(relay_res.load() == ForwardResult::Success,
                    "Relay tunnel returned Success after full 1 MB drain");
    }

    // Test 24: Half-closed client upload under backpressure drains completely (F1 client-side coverage)
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::RecvFailure};

        std::thread relay_thread([&]() {
            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(5000),
                std::chrono::seconds(30)
            );
            close(client_fd);
            close(dest_fd);
        });

        // Client sends 1 MB upload with position-dependent pattern in a separate thread
        constexpr size_t TOTAL_BYTES = 1024 * 1024;
        std::vector<char> big_upload(TOTAL_BYTES);
        for (size_t i = 0; i < TOTAL_BYTES; ++i) {
            big_upload[i] = static_cast<char>('a' + (i % 26));
        }

        std::atomic<size_t> total_sent{0};
        std::thread client_sender([&]() {
            size_t sent = 0;
            while (sent < TOTAL_BYTES) {
                ssize_t s = send(client_peer, big_upload.data() + sent, TOTAL_BYTES - sent, 0);
                if (s <= 0) break;
                sent += static_cast<size_t>(s);
            }
            total_sent = sent;
            shutdown(client_peer, SHUT_WR);
        });

        // Destination reads slowly in 4 KB chunks with short sleeps (causing backpressure on c2d)
        std::vector<char> dest_received;
        char chunk[4096];
        while (true) {
            ssize_t r = recv(dest_peer, chunk, sizeof(chunk), 0);
            if (r <= 0) break;
            dest_received.insert(dest_received.end(), chunk, chunk + r);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        // Destination sends 200 OK acknowledgement and half-closes
        const std::string ack = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        send(dest_peer, ack.data(), ack.size(), 0);
        shutdown(dest_peer, SHUT_WR);

        // Client reads acknowledgement response and verifies recv result
        char resp_buf[64];
        ssize_t ack_n = recv(client_peer, resp_buf, sizeof(resp_buf), 0);

        client_sender.join();
        close(client_peer);
        close(dest_peer);

        relay_thread.join();

        assert_test(total_sent.load() == TOTAL_BYTES,
                    "Client successfully sent full 1 MB upload");
        assert_test(dest_received == big_upload,
                    "Destination received entire 1 MB upload matching pattern under backpressure without truncation",
                    "Received " + std::to_string(dest_received.size()) + " / " + std::to_string(TOTAL_BYTES));
        assert_test(ack_n > 0 && std::string_view(resp_buf, static_cast<size_t>(ack_n)).find("200 OK") != std::string_view::npos,
                    "Client received 200 OK acknowledgement after upload drain");
        assert_test(relay_res.load() == ForwardResult::Success,
                    "Relay tunnel returned Success after full 1 MB upload drain");
    }

    // Test 25: Destination sends data and closes; client does not read (idle timeout & CPU bounding)
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        int buf_size = 4096;
        setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        setsockopt(client_peer, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

        std::atomic<ForwardResult> relay_res{ForwardResult::Success};
        std::atomic<double> cpu_sec{0.0};

        std::thread relay_thread([&]() {
            struct timespec c0, c1;
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);

            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(1500),
                std::chrono::seconds(10)
            );

            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
            cpu_sec = (c1.tv_sec - c0.tv_sec) + (c1.tv_nsec - c0.tv_nsec) / 1e9;

            close(client_fd);
            close(dest_fd);
        });

        // Destination sends enough data to fill the relay buffers (64 KB) and closes
        std::vector<char> data(64 * 1024, 'X');
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t s = send(dest_peer, data.data() + sent, data.size() - sent, 0);
            if (s <= 0) break;
            sent += static_cast<size_t>(s);
        }
        close(dest_peer);

        // Client does not read from client_peer; wait for idle timeout
        relay_thread.join();
        close(client_peer);

        assert_test(relay_res.load() == ForwardResult::Timeout,
                    "Destination closed and unread client times out with Timeout",
                    "Result was " + std::to_string(static_cast<int>(relay_res.load())));
        assert_test(cpu_sec.load() < 0.05,
                    "Destination closed and unread client CPU time bounded (<0.05s, no busy-spin)",
                    "CPU sec: " + std::to_string(cpu_sec.load()));
    }

    // Test 26: Client resets with SO_LINGER {1, 0} while destination-to-client data is pending
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::Success};
        std::atomic<double> cpu_sec{0.0};

        std::thread relay_thread([&]() {
            struct timespec c0, c1;
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);

            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(1500),
                std::chrono::seconds(10)
            );

            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1);
            cpu_sec = (c1.tv_sec - c0.tv_sec) + (c1.tv_nsec - c0.tv_nsec) / 1e9;

            close(client_fd);
            close(dest_fd);
        });

        // Destination sends data so d2c data is pending
        std::vector<char> data(32 * 1024, 'Y');
        send(dest_peer, data.data(), data.size(), 0);

        // Give relay a moment to read destination data
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Client resets with SO_LINGER {1, 0}
        struct linger sl{1, 0};
        setsockopt(client_peer, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
        close(client_peer);

        relay_thread.join();
        close(dest_peer);

        ForwardResult res = relay_res.load();
        assert_test(res == ForwardResult::RecvFailure || res == ForwardResult::ClientDisconnect,
                    "Client reset with pending data terminates promptly with failure/disconnect");
        assert_test(cpu_sec.load() < 0.05,
                    "Client reset with pending data CPU time bounded (<0.05s, no busy-spin)",
                    "CPU sec: " + std::to_string(cpu_sec.load()));
    }

    // Test 27: Client uploads 1 MB and half-closes while destination half-closes (SHUT_WR) first and reads slowly
    {
        int client_fd, client_peer;
        int dest_fd, dest_peer;
        verify_ok(create_tcp_loopback_pair(client_fd, client_peer));
        verify_ok(create_tcp_loopback_pair(dest_fd, dest_peer));

        std::atomic<ForwardResult> relay_res{ForwardResult::RecvFailure};

        std::thread relay_thread([&]() {
            relay_res = HttpForwarder::relay_tunnel(
                client_fd, dest_fd, "",
                std::chrono::milliseconds(5000),
                std::chrono::seconds(30)
            );
            close(client_fd);
            close(dest_fd);
        });

        // Destination calls shutdown(SHUT_WR) first (indicating no response data to send)
        shutdown(dest_peer, SHUT_WR);

        // Client uploads 1 MB with position-dependent pattern in a separate thread, then half-closes (SHUT_WR)
        constexpr size_t TOTAL_BYTES = 1024 * 1024;
        std::vector<char> big_upload(TOTAL_BYTES);
        for (size_t i = 0; i < TOTAL_BYTES; ++i) {
            big_upload[i] = static_cast<char>('m' + (i % 26));
        }

        std::atomic<size_t> total_sent{0};
        std::thread client_sender([&]() {
            size_t sent = 0;
            while (sent < TOTAL_BYTES) {
                ssize_t s = send(client_peer, big_upload.data() + sent, TOTAL_BYTES - sent, 0);
                if (s <= 0) break;
                sent += static_cast<size_t>(s);
            }
            total_sent = sent;
            shutdown(client_peer, SHUT_WR);
        });

        // Destination reads slowly in 4 KB chunks with short sleeps (causing backpressure on c2d)
        std::vector<char> dest_received;
        char chunk[4096];
        while (true) {
            ssize_t r = recv(dest_peer, chunk, sizeof(chunk), 0);
            if (r <= 0) break;
            dest_received.insert(dest_received.end(), chunk, chunk + r);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        client_sender.join();
        close(client_peer);
        close(dest_peer);

        relay_thread.join();

        assert_test(total_sent.load() == TOTAL_BYTES,
                    "Client successfully sent full 1 MB upload");
        assert_test(dest_received == big_upload,
                    "Destination received full 1 MB upload byte-for-byte after destination half-close",
                    "Received " + std::to_string(dest_received.size()) + " / " + std::to_string(TOTAL_BYTES));
        assert_test(relay_res.load() == ForwardResult::Success,
                    "Relay tunnel returned Success for client upload with destination half-close",
                    "Result was " + std::to_string(static_cast<int>(relay_res.load())));
    }

    std::cout << "\nTest Results: " << g_passed << " passed, " << g_failed << " failed." << std::endl;
    return g_failed == 0 ? 0 : 1;
}
