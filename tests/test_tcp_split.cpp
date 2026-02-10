#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"
#include "test_common.h"

#include <cassert>

void test_tcp_split_basic() {
    printf("test_tcp_split_basic... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    const char* message = "Hello, this is a test message for TCP split!";
    size_t msg_len = strlen(message);

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

    auto received = server.recv_all(msg_len);
    assert(received.size() == msg_len);
    assert(memcmp(received.data(), message, msg_len) == 0);

    close_socket(client);
    printf("OK\n");
}

void test_tcp_split_multiple_positions() {
    printf("test_tcp_split_multiple_positions... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

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

    close_socket(client);
    printf("OK\n");
}

void test_no_tactic() {
    printf("test_no_tactic... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

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

    close_socket(client);
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
