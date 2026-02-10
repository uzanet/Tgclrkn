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

// Simulated TLS ClientHello with SNI
std::vector<uint8_t> make_client_hello_with_sni(const std::string& hostname) {
    // Build a minimal but valid TLS ClientHello with SNI extension
    std::vector<uint8_t> sni_ext;
    // SNI extension data:
    // server_name_list_length (2) + server_name_type (1) + name_length (2) + name
    uint16_t name_len = static_cast<uint16_t>(hostname.size());
    uint16_t list_len = name_len + 3;
    sni_ext.push_back(static_cast<uint8_t>(list_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(list_len & 0xFF));
    sni_ext.push_back(0x00);  // host_name type
    sni_ext.push_back(static_cast<uint8_t>(name_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(name_len & 0xFF));
    sni_ext.insert(sni_ext.end(), hostname.begin(), hostname.end());

    // Extensions block: SNI extension
    std::vector<uint8_t> extensions;
    extensions.push_back(0x00); extensions.push_back(0x00);  // SNI ext type
    uint16_t ext_data_len = static_cast<uint16_t>(sni_ext.size());
    extensions.push_back(static_cast<uint8_t>(ext_data_len >> 8));
    extensions.push_back(static_cast<uint8_t>(ext_data_len & 0xFF));
    extensions.insert(extensions.end(), sni_ext.begin(), sni_ext.end());

    uint16_t extensions_len = static_cast<uint16_t>(extensions.size());

    // ClientHello body
    std::vector<uint8_t> hello_body;
    hello_body.push_back(0x03); hello_body.push_back(0x03);  // TLS 1.2
    // 32 bytes random
    for (int i = 0; i < 32; ++i) hello_body.push_back(static_cast<uint8_t>(i));
    hello_body.push_back(0x00);  // session_id length = 0
    hello_body.push_back(0x00); hello_body.push_back(0x02);  // cipher suites len
    hello_body.push_back(0x00); hello_body.push_back(0xFF);  // cipher
    hello_body.push_back(0x01);  // compression methods len
    hello_body.push_back(0x00);  // null compression
    hello_body.push_back(static_cast<uint8_t>(extensions_len >> 8));
    hello_body.push_back(static_cast<uint8_t>(extensions_len & 0xFF));
    hello_body.insert(hello_body.end(), extensions.begin(), extensions.end());

    // Handshake header
    uint32_t hello_len = static_cast<uint32_t>(hello_body.size());
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);  // ClientHello
    handshake.push_back(static_cast<uint8_t>((hello_len >> 16) & 0xFF));
    handshake.push_back(static_cast<uint8_t>((hello_len >> 8) & 0xFF));
    handshake.push_back(static_cast<uint8_t>(hello_len & 0xFF));
    handshake.insert(handshake.end(), hello_body.begin(), hello_body.end());

    // TLS record
    uint16_t record_len = static_cast<uint16_t>(handshake.size());
    std::vector<uint8_t> record;
    record.push_back(0x16);  // Handshake
    record.push_back(0x03); record.push_back(0x01);  // TLS 1.0 (record version)
    record.push_back(static_cast<uint8_t>(record_len >> 8));
    record.push_back(static_cast<uint8_t>(record_len & 0xFF));
    record.insert(record.end(), handshake.begin(), handshake.end());

    return record;
}

} // anonymous namespace

void test_tls_split_with_sni() {
    printf("test_tls_split_with_sni... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });
    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    auto hello = make_client_hello_with_sni("web.telegram.org");

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::TcpSplit;
    // Auto-detect split position based on SNI
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(hello.data(), hello.size());
    assert(result.success);

    auto received = server.recv_all(hello.size() + 64);
    assert(received.size() >= hello.size());

    close(client);
    printf("OK\n");
}

void test_tls_record_split_with_sni() {
    printf("test_tls_record_split_with_sni... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });
    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    auto hello = make_client_hello_with_sni("web.telegram.org");

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::TlsRecordSplit;
    config.split_position = 10;  // Split TLS record at position 10
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(hello.data(), hello.size());
    assert(result.success);

    // The server receives two TLS records instead of one.
    // Total data = original + extra 5-byte TLS header
    auto received = server.recv_all(hello.size() + 64);
    assert(received.size() == hello.size() + 5);  // +5 for the extra TLS record header

    // Verify both are valid TLS records
    assert(received[0] == 0x16);  // First record: Handshake

    close(client);
    printf("OK\n");
}

void test_combined_split_and_oob() {
    printf("test_combined_split_and_oob... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });
    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    const char* message = "Test message for combined tactics";
    size_t msg_len = strlen(message);

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::OOB;
    config.split_position = 5;
    config.oob_byte = 0x42;
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(message), msg_len);
    assert(result.success);

    // OOB byte is handled separately by TCP stack
    auto received = server.recv_all(msg_len + 64);
    assert(received.size() >= msg_len);

    close(client);
    printf("OK\n");
}

void test_bypass_cutoff() {
    printf("test_bypass_cutoff... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });
    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::TcpSplit;
    config.split_position = 3;
    config.bypass_cutoff = 20;  // Only apply bypass to first 20 bytes
    bypass.setConfig(config);
    bypass.onConnected();

    // First write: within cutoff — tactics applied
    const char* msg1 = "First write";
    WriteResult r1 = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(msg1), strlen(msg1));
    assert(r1.success);
    assert(bypass.bypassActive());  // Still within cutoff

    // Second write: exceeds cutoff — passthrough
    const char* msg2 = "Second write that pushes us past cutoff";
    WriteResult r2 = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(msg2), strlen(msg2));
    assert(r2.success);

    auto received = server.recv_all(strlen(msg1) + strlen(msg2) + 64);
    assert(received.size() >= strlen(msg1) + strlen(msg2));

    close(client);
    printf("OK\n");
}

int main() {
    printf("=== Integration Tests ===\n");
    test_tls_split_with_sni();
    test_tls_record_split_with_sni();
    test_combined_split_and_oob();
    test_bypass_cutoff();
    printf("All integration tests passed!\n");
    return 0;
}
