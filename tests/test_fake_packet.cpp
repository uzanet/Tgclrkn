#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"
#include "test_common.h"

#include <cassert>
#include <algorithm>

void test_fake_rst_sends_real_data() {
    printf("test_fake_rst_sends_real_data... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

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

    auto received = server.recv_all(msg_len + 128);
    assert(received.size() >= msg_len);

    auto it = std::search(received.begin(), received.end(),
                          reinterpret_cast<const uint8_t*>(message),
                          reinterpret_cast<const uint8_t*>(message) + msg_len);
    assert(it != received.end());

    close_socket(client);
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

    close_socket(client);
    printf("OK\n");
}

int main() {
    printf("=== Fake Packet Tests ===\n");
    test_fake_rst_sends_real_data();
    test_fake_data_sends_real_data();
    printf("All fake packet tests passed!\n");
    return 0;
}
