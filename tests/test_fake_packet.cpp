#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
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
        addr.sin_port = 0;
        if (::bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0)
            return false;
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
#ifndef _WIN32
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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
        if (client_fd != INVALID_SOCK) close(client_fd);
        if (listen_fd != INVALID_SOCK) close(listen_fd);
    }
};

socket_t connect_to(int port) {
    socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0)
        return INVALID_SOCK;
    return fd;
}

} // anonymous namespace

void test_fake_rst_sends_real_data() {
    printf("test_fake_rst_sends_real_data... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    // On loopback, TTL=1 fake packets still arrive (no router hops)
    // So the server will see both fake and real data.
    // In a real network, the fake packet would be dropped.
    const char* message = "Real message after fake RST";
    size_t msg_len = strlen(message);

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::FakeRst;
    config.fake_ttl = 1;
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(message), msg_len);
    assert(result.success);
    assert(result.bytes_written == static_cast<int>(msg_len));

    // On loopback we'll get both fake + real data
    // Just verify the real data is there
    auto received = server.recv_all(msg_len + 128);
    assert(received.size() >= msg_len);

    // Find the real message in the received data
    auto it = std::search(received.begin(), received.end(),
                          reinterpret_cast<const uint8_t*>(message),
                          reinterpret_cast<const uint8_t*>(message) + msg_len);
    assert(it != received.end());

    close(client);
    printf("OK\n");
}

void test_fake_data_sends_real_data() {
    printf("test_fake_data_sends_real_data... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    const char* message = "Real message after fake data";
    size_t msg_len = strlen(message);

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::FakeData;
    config.fake_ttl = 1;
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(message), msg_len);
    assert(result.success);

    auto received = server.recv_all(msg_len + 128);
    assert(received.size() >= msg_len);

    auto it = std::search(received.begin(), received.end(),
                          reinterpret_cast<const uint8_t*>(message),
                          reinterpret_cast<const uint8_t*>(message) + msg_len);
    assert(it != received.end());

    close(client);
    printf("OK\n");
}

int main() {
    printf("=== Fake Packet Tests ===\n");
    test_fake_rst_sends_real_data();
    test_fake_data_sends_real_data();
    printf("All fake packet tests passed!\n");
    return 0;
}
