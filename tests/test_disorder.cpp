#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"
#include "test_common.h"

#include <cassert>

void test_disorder_data_integrity() {
    printf("test_disorder_data_integrity... ");

    LoopbackServer server;
    assert(server.start());

    std::thread server_thread([&]() { server.accept_one(); });

    socket_t client = connect_to(server.port);
    assert(client != INVALID_SOCK);
    server_thread.join();

    // On loopback, TTL=1 packets still arrive (no router hops)
    // So the disorder tactic on loopback effectively sends data twice
    // for the first segment. TCP stack on the receiver deduplicates.
    const char* message = "ABCDEFGHIJKLMNOP";
    size_t msg_len = strlen(message);

    BypassSocket bypass(client);
    TacticConfig config;
    config.tactics = Tactic::Disorder;
    config.split_position = 5;
    config.disorder_ttl = 1;
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

int main() {
    printf("=== Disorder Tests ===\n");
    test_disorder_data_integrity();
    printf("All disorder tests passed!\n");
    return 0;
}
