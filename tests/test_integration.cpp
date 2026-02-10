#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"
#include "test_common.h"

#include <cassert>
#include <string>

namespace {

// Simulated TLS ClientHello with SNI
std::vector<uint8_t> make_client_hello_with_sni(const std::string& hostname) {
    std::vector<uint8_t> sni_ext;
    uint16_t name_len = static_cast<uint16_t>(hostname.size());
    uint16_t list_len = name_len + 3;
    sni_ext.push_back(static_cast<uint8_t>(list_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(list_len & 0xFF));
    sni_ext.push_back(0x00);  // host_name type
    sni_ext.push_back(static_cast<uint8_t>(name_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(name_len & 0xFF));
    sni_ext.insert(sni_ext.end(), hostname.begin(), hostname.end());

    std::vector<uint8_t> extensions;
    extensions.push_back(0x00); extensions.push_back(0x00);  // SNI ext type
    uint16_t ext_data_len = static_cast<uint16_t>(sni_ext.size());
    extensions.push_back(static_cast<uint8_t>(ext_data_len >> 8));
    extensions.push_back(static_cast<uint8_t>(ext_data_len & 0xFF));
    extensions.insert(extensions.end(), sni_ext.begin(), sni_ext.end());

    uint16_t extensions_len = static_cast<uint16_t>(extensions.size());

    std::vector<uint8_t> hello_body;
    hello_body.push_back(0x03); hello_body.push_back(0x03);  // TLS 1.2
    for (int i = 0; i < 32; ++i) hello_body.push_back(static_cast<uint8_t>(i));
    hello_body.push_back(0x00);  // session_id length = 0
    hello_body.push_back(0x00); hello_body.push_back(0x02);  // cipher suites len
    hello_body.push_back(0x00); hello_body.push_back(0xFF);  // cipher
    hello_body.push_back(0x01);  // compression methods len
    hello_body.push_back(0x00);  // null compression
    hello_body.push_back(static_cast<uint8_t>(extensions_len >> 8));
    hello_body.push_back(static_cast<uint8_t>(extensions_len & 0xFF));
    hello_body.insert(hello_body.end(), extensions.begin(), extensions.end());

    uint32_t hello_len = static_cast<uint32_t>(hello_body.size());
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);  // ClientHello
    handshake.push_back(static_cast<uint8_t>((hello_len >> 16) & 0xFF));
    handshake.push_back(static_cast<uint8_t>((hello_len >> 8) & 0xFF));
    handshake.push_back(static_cast<uint8_t>(hello_len & 0xFF));
    handshake.insert(handshake.end(), hello_body.begin(), hello_body.end());

    uint16_t record_len = static_cast<uint16_t>(handshake.size());
    std::vector<uint8_t> record;
    record.push_back(0x16);  // Handshake
    record.push_back(0x03); record.push_back(0x01);  // TLS 1.0
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
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(hello.data(), hello.size());
    assert(result.success);

    auto received = server.recv_all(hello.size() + 64);
    assert(received.size() >= hello.size());

    close_socket(client);
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
    config.split_position = 10;
    bypass.setConfig(config);
    bypass.onConnected();

    WriteResult result = bypass.writeWithBypass(hello.data(), hello.size());
    assert(result.success);

    auto received = server.recv_all(hello.size() + 64);
    assert(received.size() == hello.size() + 5);  // +5 for extra TLS record header

    assert(received[0] == 0x16);  // First record: Handshake

    close_socket(client);
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

    auto received = server.recv_all(msg_len + 64);
    assert(received.size() >= msg_len);

    close_socket(client);
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
    config.bypass_cutoff = 20;
    bypass.setConfig(config);
    bypass.onConnected();

    const char* msg1 = "First write";
    WriteResult r1 = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(msg1), strlen(msg1));
    assert(r1.success);
    assert(bypass.bypassActive());

    const char* msg2 = "Second write that pushes us past cutoff";
    WriteResult r2 = bypass.writeWithBypass(
        reinterpret_cast<const uint8_t*>(msg2), strlen(msg2));
    assert(r2.success);

    auto received = server.recv_all(strlen(msg1) + strlen(msg2) + 64);
    assert(received.size() >= strlen(msg1) + strlen(msg2));

    close_socket(client);
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
