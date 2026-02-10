#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

using namespace dpibypass;

namespace {

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

        if (::listen(listen_fd, 1) != 0) return false;
        return true;
    }

    socket_t accept_one() {
        client_fd = ::accept(listen_fd, nullptr, nullptr);
        return client_fd;
    }

    std::vector<uint8_t> recv_all(size_t expected, int timeout_ms = 2000) {
        std::vector<uint8_t> result;
        result.reserve(expected);

#ifdef _WIN32
        DWORD tv = static_cast<DWORD>(timeout_ms);
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
#endif
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));

        uint8_t buf[4096];
        while (result.size() < expected) {
            int n = ::recv(client_fd, reinterpret_cast<char*>(buf), sizeof(buf), 0);
            if (n <= 0) break;
            result.insert(result.end(), buf, buf + n);
        }
        return result;
    }

    ~LoopbackServer() {
        if (client_fd != INVALID_SOCK) {
#ifdef _WIN32
            closesocket(client_fd);
#else
            close(client_fd);
#endif
        }
        if (listen_fd != INVALID_SOCK) {
#ifdef _WIN32
            closesocket(listen_fd);
#else
            close(listen_fd);
#endif
        }
    }
};

socket_t connect_to(int port) {
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

} // anonymous namespace

void test_tcp_split_basic() {
    printf("test_tcp_split_basic... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() {
        server.accept_one();
    });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    // Prepare test data
    const char* message = "Hello, this is a test message for TCP split!";
    size_t msg_len = strlen(message);

    // Create bypass socket with TCP split at position 5
    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::TcpSplit;
    config.split_position = 5;
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(message), msg_len);
    assert(result.success);
    assert(result.bytes_written == static_cast<int>(msg_len));

    // Server should receive complete data
    auto received = server.recv_all(msg_len);
    assert(received.size() == msg_len);
    assert(memcmp(received.data(), message, msg_len) == 0);

#ifdef _WIN32
    closesocket(client);
#else
    close(client);
#endif

    printf("OK\n");
}

void test_tcp_split_multiple_positions() {
    printf("test_tcp_split_multiple_positions... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() {
        server.accept_one();
    });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    const char* message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t msg_len = strlen(message);

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::TcpSplit;
    config.multi_split_positions = {3, 10, 20};
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(message), msg_len);
    assert(result.success);

    auto received = server.recv_all(msg_len);
    assert(received.size() == msg_len);
    assert(memcmp(received.data(), message, msg_len) == 0);

#ifdef _WIN32
    closesocket(client);
#else
    close(client);
#endif

    printf("OK\n");
}

void test_no_tactic() {
    printf("test_no_tactic... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() {
        server.accept_one();
    });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    const char* message = "Plain send without tactics";
    size_t msg_len = strlen(message);

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::None;
    bypass.setConfig(config);

    WriteResult result = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(message), msg_len);
    assert(result.success);
    assert(result.bytes_written == static_cast<int>(msg_len));

    auto received = server.recv_all(msg_len);
    assert(received.size() == msg_len);
    assert(memcmp(received.data(), message, msg_len) == 0);

#ifdef _WIN32
    closesocket(client);
#else
    close(client);
#endif

    printf("OK\n");
}

int main() {
    printf("=== TCP Split Tests ===\n");
    test_tcp_split_basic();
    test_tcp_split_multiple_positions();
    test_no_tactic();
    printf("All TCP split tests passed!\n");
    return 0;
}
