#include <iostream>
#include <cstring>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <mutex>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "http_parser.h"
#include "thread_pool.h"
#include "authenticator.h"

/*
 * Socket Lifecycle:
 * 1. socket()  - Create an endpoint for network communication (IPv4 TCP).
 * 2. bind()    - Bind the socket to a local address (127.0.0.1) and port (8080).
 * 3. listen()  - Mark the socket as passive, ready to accept incoming connections.
 * 4. accept()  - Extract the first connection request on the queue and create a new connected socket.
 * 5. recv()    - Receive data from the connected client socket (handled by worker thread).
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
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << "Accepted connection from " << client_ip << ":" << client_port << std::endl;
    }

    // 5. Receive data from client
    char buffer[1024];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv failed");
    } else if (bytes_received == 0) {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cout << "Client disconnected without sending data." << std::endl;
    } else {
        // Attempt to parse received data as an HTTP request
        HttpRequest req = HttpParser::parse(std::string_view(buffer, static_cast<size_t>(bytes_received)));
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

        // 6. Send response to authenticated client
        const char response[] = "Hello from SecureProxyGateway TCP server!\n";
        ssize_t bytes_sent = send(client_fd, response, sizeof(response) - 1, 0);
        if (bytes_sent < 0) {
            perror("send failed");
        }
    }

    // 7. Close client connection
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
