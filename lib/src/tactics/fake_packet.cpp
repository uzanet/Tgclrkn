#include "tactic_base.h"
#include "dpibypass/socket_wrapper.h"

#include <cstring>
#include <array>

namespace dpibypass {
namespace tactics {

namespace {

// Generate a fake TLS ClientHello with garbage SNI
// This confuses stateful DPI that tracks the first ClientHello
std::array<uint8_t, 64> make_fake_tls_hello() {
    std::array<uint8_t, 64> fake{};
    // TLS record header: ContentType=Handshake(22), Version=TLS1.0(0x0301), Length
    fake[0] = 0x16;  // Handshake
    fake[1] = 0x03;  // TLS 1.0
    fake[2] = 0x01;
    fake[3] = 0x00;  // Length high
    fake[4] = 0x3B;  // Length low (59 bytes)
    // HandshakeType=ClientHello(1)
    fake[5] = 0x01;
    // Fill rest with random-looking but deterministic data
    for (size_t i = 6; i < fake.size(); ++i) {
        fake[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
    }
    return fake;
}

} // anonymous namespace

WriteResult fake_rst_write(socket_t fd, const uint8_t* data, size_t len,
                           const TacticConfig& config) {
    // Strategy:
    // 1. Save original TTL
    // 2. Set TTL to config.fake_ttl (typically 1)
    // 3. Send fake data (will be dropped by first router hop)
    // 4. Restore original TTL
    // 5. Send real data
    //
    // The DPI sees the fake data first and may cache it,
    // but the packet never reaches the server.

    int orig_ttl = platform::get_ttl(fd);
    if (orig_ttl <= 0) {
        orig_ttl = 64;  // Fallback
    }

    // Send fake packet with low TTL
    platform::set_ttl(fd, config.fake_ttl);

    auto fake = make_fake_tls_hello();
    platform::send_data(fd, fake.data(), fake.size());
    // We don't care if the fake send fails — it's expected to be dropped

    // Restore original TTL
    platform::set_ttl(fd, orig_ttl);

    // Now send real data
    int sent = platform::send_data(fd, data, len);
    if (sent < 0) {
        return WriteResult::fail("send real data after fake RST failed");
    }

    return WriteResult::ok(sent);
}

WriteResult fake_data_write(socket_t fd, const uint8_t* data, size_t len,
                            const TacticConfig& config) {
    // Similar to fake_rst but sends random garbage data instead of fake TLS
    int orig_ttl = platform::get_ttl(fd);
    if (orig_ttl <= 0) {
        orig_ttl = 64;
    }

    // Create garbage payload of same length as real data (up to 64 bytes)
    size_t fake_len = std::min(len, size_t(64));
    std::array<uint8_t, 64> garbage{};
    for (size_t i = 0; i < fake_len; ++i) {
        garbage[i] = static_cast<uint8_t>((i * 31 + 97) & 0xFF);
    }

    platform::set_ttl(fd, config.fake_ttl);
    platform::send_data(fd, garbage.data(), fake_len);
    platform::set_ttl(fd, orig_ttl);

    int sent = platform::send_data(fd, data, len);
    if (sent < 0) {
        return WriteResult::fail("send real data after fake data failed");
    }

    return WriteResult::ok(sent);
}

} // namespace tactics
} // namespace dpibypass
