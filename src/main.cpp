#include <iostream>
#include <cstring>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "http_parser.h"

/*
 * Socket Lifecycle:
 * 1. socket()  - Create an endpoint for network communication (IPv4 TCP).
 * 2. bind()    - Bind the socket to a local address (127.0.0.1) and port (8080).
 * 3. listen()  - Mark the socket as passive, ready to accept incoming connections.
 * 4. accept()  - Extract the first connection request on the queue and create a new connected socket.
 * 5. recv()    - Receive data from the connected client socket.
 * 6. send()    - Send response data back to the client socket.
 * 7. close()   - Close the client connection and listening server socket when done.
 */

namespace {
volatile sig_atomic_t g_running = 1;

void handle_signal(int /*signum*/) {
    g_running = 0;
}
}

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
        std::cout << "Accepted connection from " << client_ip_buf << ":" << ntohs(client_addr.sin_port) << std::endl;

        // 5. Receive data from client
        char buffer[1024];
        std::memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received < 0) {
            perror("recv failed");
        } else if (bytes_received == 0) {
            std::cout << "Client disconnected without sending data." << std::endl;
        } else {
            std::cout << "Received " << bytes_received << " bytes: " << buffer << std::endl;

            // Attempt to parse received data as an HTTP request
            HttpRequest req = HttpParser::parse(std::string_view(buffer, static_cast<size_t>(bytes_received)));
            if (req.valid) {
                std::cout << "Parsed HTTP Request: method=" << req.method
                          << " host=" << req.host
                          << " port=" << req.port
                          << " path=" << req.path << std::endl;
            }

            // 6. Send response to client
            const char response[] = "Hello from SecureProxyGateway TCP server!\n";
            ssize_t bytes_sent = send(client_fd, response, sizeof(response) - 1, 0);
            if (bytes_sent < 0) {
                perror("send failed");
            }
        }

        // 7. Close client connection
        close(client_fd);
        std::cout << "Closed client connection." << std::endl;
    }

    std::cout << "Shutting down server..." << std::endl;
    close(server_fd);
    return 0;
}
