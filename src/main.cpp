#include <iostream>
#include <cstring>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <chrono>
#include <algorithm>
#include <mutex>
#include <poll.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "http_parser.h"
#include "thread_pool.h"
#include "authenticator.h"
#include "http_forwarder.h"

/*
 * Socket Lifecycle:
 * 1. socket()  - Create an endpoint for network communication (IPv4 TCP).
 * 2. bind()    - Bind the socket to a local address (127.0.0.1) and port (8080).
 * 3. listen()  - Mark the socket as passive, ready to accept incoming connections.
 * 4. accept()  - Extract the first connection request on the queue and create a new connected socket.
 * 5. recv()    - Receive data from client in a read loop until headers are complete or timeout.
 * 6. send()    - Send response data back to the client socket (handled by worker thread).
 * 7. close()   - Close the client connection and listening server socket when done.
 */

namespace {
volatile sig_atomic_t g_running = 1;
std::mutex g_log_mutex;

void handle_signal(int /*signum*/) {
    g_running = 0;
}

void process_client(int client_fd, const std::string& client_ip, uint16_t client_port) {
    // Set 5-second socket receive and send timeouts
    struct timeval tv{};
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
    }
    if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_SNDTIMEO failed");
    }

    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << "Accepted connection from " << client_ip << ":" << client_port << std::endl;
    }

    std::string request_buffer;
    request_buffer.reserve(HttpParser::MAX_HEADER_BLOCK_SIZE);

    char chunk[1024];
    HttpRequest req;

    // Total 10-second header read deadline
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    // HTTP Read Loop: continue reading until complete, error, or 8 KB limit reached
    while (request_buffer.size() < HttpParser::MAX_HEADER_BLOCK_SIZE) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Client " << client_ip << ":" << client_port << " header-read timeout." << std::endl;
                std::cout << "Closed client connection." << std::endl;
            }
            close(client_fd);
            return;
        }

        auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (remaining_ms <= 0) {
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Client " << client_ip << ":" << client_port << " header-read timeout." << std::endl;
                std::cout << "Closed client connection." << std::endl;
            }
            close(client_fd);
            return;
        }

        struct pollfd pfd{};
        pfd.fd = client_fd;
        pfd.events = POLLIN;

        int poll_res = poll(&pfd, 1, static_cast<int>(remaining_ms));
        if (poll_res == 0) {
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Client " << client_ip << ":" << client_port << " header-read timeout." << std::endl;
                std::cout << "Closed client connection." << std::endl;
            }
            close(client_fd);
            return;
        }
        if (poll_res < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll failed");
            close(client_fd);
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Closed client connection." << std::endl;
            }
            return;
        }

        size_t space_left = HttpParser::MAX_HEADER_BLOCK_SIZE - request_buffer.size();
        size_t to_read = std::min(sizeof(chunk), space_left);

        ssize_t bytes_read = recv(client_fd, chunk, to_read, 0);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Client " << client_ip << ":" << client_port << " timed out waiting for request." << std::endl;
            } else {
                perror("recv failed");
            }
            close(client_fd);
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Closed client connection." << std::endl;
            }
            return;
        }

        if (bytes_read == 0) {
            // Client closed connection without completing request
            close(client_fd);
            {
                std::lock_guard<std::mutex> lock(g_log_mutex);
                std::cout << "Closed client connection." << std::endl;
            }
            return;
        }

        request_buffer.append(chunk, static_cast<size_t>(bytes_read));

        req = HttpParser::parse(request_buffer);
        if (!req.is_incomplete()) {
            break;
        }
    }

    // If buffer reached 8 KB limit without receiving header terminator, treat as error
    if (req.is_incomplete()) {
        req.status = ParseStatus::Error;
        req.valid = false;
        req.error_message = "Header block exceeds maximum size of 8 KB";
    }

    if (!req.valid) {
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "Invalid HTTP request from client " << client_ip << ":" << client_port
                      << " - sending 400 Bad Request" << std::endl;
        }
        std::string resp_400 = HttpParser::make_400_response();
        ssize_t sent = send(client_fd, resp_400.data(), resp_400.size(), 0);
        if (sent < 0) {
            perror("send failed");
        }
        close(client_fd);
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "Closed client connection." << std::endl;
        }
        return;
    }

    // Safe logging of request metadata with query parameters stripped from path
    {
        std::string safe_path = HttpParser::sanitize_path(req.path);
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << "Parsed HTTP Request: method=" << req.method
                  << " host=" << req.host
                  << " port=" << req.port
                  << " path=" << safe_path << std::endl;
    }

    // Authenticate client request
    Authenticator auth;
    if (!auth.authenticate(req.proxy_authorization)) {
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "Authentication failed for client " << client_ip << ":" << client_port
                      << " - sending 407 Proxy Authentication Required" << std::endl;
        }
        std::string resp_407 = Authenticator::make_407_response();
        ssize_t sent = send(client_fd, resp_407.data(), resp_407.size(), 0);
        if (sent < 0) {
            perror("send failed");
        }
        close(client_fd);
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "Closed client connection." << std::endl;
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << "Authentication successful for client " << client_ip << ":" << client_port << std::endl;
    }

    if (req.method == "CONNECT") {
        std::string resp_501 = "HTTP/1.1 501 Not Implemented\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: 16\r\n"
                               "Connection: close\r\n"
                               "\r\n"
                               "Not Implemented\n";
        send(client_fd, resp_501.data(), resp_501.size(), 0);
        close(client_fd);
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            std::cout << "Closed client connection." << std::endl;
        }
        return;
    }

    // Forward plain HTTP request
    std::string initial_body = (request_buffer.size() > req.header_length)
        ? request_buffer.substr(req.header_length)
        : "";

    HttpForwarder forwarder;
    forwarder.forward(req, initial_body, client_fd);

    // Close client connection
    close(client_fd);
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << "Closed client connection." << std::endl;
    }
}

} // namespace

int main() {
    std::cout << "Secure Proxy Gateway starting..." << std::endl;

    struct sigaction sa{};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Do not restart interrupted syscalls so accept() exits cleanly
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    const char* server_ip = "127.0.0.1";
    const uint16_t server_port = 8080;

    // 1. Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket creation failed");
        return 1;
    }

    // Set SO_REUSEADDR so the server port can be rebound immediately upon restart
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(server_fd);
        return 1;
    }

    // Prepare address structure
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(server_fd);
        return 1;
    }

    // 2. Bind socket to address and port
    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }

    // 3. Listen for incoming connections
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        close(server_fd);
        return 1;
    }

    // Initialize thread pool with 4 worker threads
    ThreadPool pool(4);
    std::cout << "Thread pool started with 4 worker threads." << std::endl;
    std::cout << "Server listening on " << server_ip << ":" << server_port << "..." << std::endl;

    while (g_running) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        // 4. Accept client connection
        int client_fd = accept(server_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            if (!g_running) {
                break;
            }
            perror("accept failed");
            continue;
        }

        char client_ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_buf, sizeof(client_ip_buf));
        std::string client_ip(client_ip_buf);
        uint16_t client_port = ntohs(client_addr.sin_port);

        // Enqueue client request handling task to the thread pool
        pool.enqueue([client_fd, client_ip, client_port]() {
            process_client(client_fd, client_ip, client_port);
        });
    }

    std::cout << "Shutting down server..." << std::endl;
    close(server_fd);
    pool.stop();
    return 0;
}
