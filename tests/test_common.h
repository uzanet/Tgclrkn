#pragma once

// Cross-platform socket helpers for tests

#include "dpibypass/socket_wrapper.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <thread>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socklen_t = int;

inline void close_socket(socket_t fd) { closesocket(fd); }

struct WinsockInit {
    WinsockInit() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WinsockInit() { WSACleanup(); }
};
static WinsockInit _wsa_init;

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

inline void close_socket(socket_t fd) { close(fd); }
#endif

using namespace dpibypass;

struct LoopbackServer {
    socket_t listen_fd = INVALID_SOCK;
    socket_t client_fd = INVALID_SOCK;
    int port = 0;

    bool start() {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd == INVALID_SOCK) return false;

        int reuse = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  // Auto-assign

        if (::bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)) != 0) {
            return false;
        }

        socklen_t addrlen = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &addrlen);
        port = ntohs(addr.sin_port);

        return ::listen(listen_fd, 1) == 0;
    }

    socket_t accept_one() {
        client_fd = ::accept(listen_fd, nullptr, nullptr);
        return client_fd;
    }

    std::vector<uint8_t> recv_all(size_t max_bytes, int timeout_ms = 2000) {
        std::vector<uint8_t> result;

#ifdef _WIN32
        DWORD tv = static_cast<DWORD>(timeout_ms);
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif

        uint8_t buf[4096];
        while (result.size() < max_bytes) {
            int n = ::recv(client_fd, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n <= 0) break;
            result.insert(result.end(), buf, buf + n);
        }
        return result;
    }

    ~LoopbackServer() {
        if (client_fd != INVALID_SOCK) close_socket(client_fd);
        if (listen_fd != INVALID_SOCK) close_socket(listen_fd);
    }
};

inline socket_t connect_to(int port) {
    socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        return INVALID_SOCK;
    }
    return fd;
}
