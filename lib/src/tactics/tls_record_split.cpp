#include "tactic_base.h"
#include "dpibypass/socket_wrapper.h"

#include <cstring>
#include <vector>

namespace dpibypass {
namespace tactics {

namespace {

// TLS record header is 5 bytes:
// [ContentType:1][ProtocolVersion:2][Length:2]
constexpr size_t TLS_RECORD_HEADER_SIZE = 5;
constexpr uint8_t TLS_HANDSHAKE = 0x16;

bool is_tls_record(const uint8_t* data, size_t len) {
    if (len < TLS_RECORD_HEADER_SIZE) return false;
    // Check ContentType (must be a valid TLS content type)
    uint8_t ct = data[0];
    if (ct < 0x14 || ct > 0x18) return false;
    // Check version (0x0301 = TLS1.0, 0x0303 = TLS1.2, etc.)
    if (data[1] != 0x03) return false;
    return true;
}

uint16_t read_u16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

void write_u16(uint8_t* p, uint16_t val) {
    p[0] = static_cast<uint8_t>(val >> 8);
    p[1] = static_cast<uint8_t>(val & 0xFF);
}

} // anonymous namespace

WriteResult tls_record_split_write(socket_t fd, const uint8_t* data, size_t len,
                                   const TacticConfig& config) {
    // TLS Record Split strategy:
    //
    // Instead of splitting at the TCP level, we split the TLS record itself
    // into two smaller TLS records. Each record has its own 5-byte header.
    //
    // Original: [Header1][Payload: ClientHello...]
    // Split:    [Header1a][Payload_part1] [Header1b][Payload_part2]
    //
    // This defeats DPI that only inspects the first TLS record looking for SNI.

    if (!is_tls_record(data, len)) {
        // Not a TLS record — send as-is
        int sent = platform::send_data(fd, data, len);
        if (sent < 0) return WriteResult::fail("tls_split: not TLS, send failed");
        return WriteResult::ok(sent);
    }

    uint16_t record_len = read_u16(data + 3);
    size_t total_record = TLS_RECORD_HEADER_SIZE + record_len;

    if (total_record > len || record_len <= 1) {
        // Incomplete record or too small to split
        int sent = platform::send_data(fd, data, len);
        if (sent < 0) return WriteResult::fail("tls_split: send failed");
        return WriteResult::ok(sent);
    }

    // Determine split point within the TLS payload
    int split_pos = config.split_position;
    if (split_pos <= 0 || split_pos >= static_cast<int>(record_len)) {
        split_pos = 1;  // Split after first payload byte
    }

    uint16_t part1_len = static_cast<uint16_t>(split_pos);
    uint16_t part2_len = record_len - part1_len;

    // Build first TLS record: same type/version, shorter payload
    std::vector<uint8_t> record1(TLS_RECORD_HEADER_SIZE + part1_len);
    record1[0] = data[0];  // ContentType
    record1[1] = data[1];  // Version major
    record1[2] = data[2];  // Version minor
    write_u16(record1.data() + 3, part1_len);
    std::memcpy(record1.data() + TLS_RECORD_HEADER_SIZE,
                data + TLS_RECORD_HEADER_SIZE, part1_len);

    // Build second TLS record
    std::vector<uint8_t> record2(TLS_RECORD_HEADER_SIZE + part2_len);
    record2[0] = data[0];
    record2[1] = data[1];
    record2[2] = data[2];
    write_u16(record2.data() + 3, part2_len);
    std::memcpy(record2.data() + TLS_RECORD_HEADER_SIZE,
                data + TLS_RECORD_HEADER_SIZE + part1_len, part2_len);

    platform::set_tcp_nodelay(fd, true);

    // Send first record
    int sent1 = platform::send_data(fd, record1.data(), record1.size());
    if (sent1 < 0) {
        return WriteResult::fail("tls_split: send record1 failed");
    }

    // Send second record
    int sent2 = platform::send_data(fd, record2.data(), record2.size());
    if (sent2 < 0) {
        return WriteResult::fail("tls_split: send record2 failed");
    }

    // If there's data after the first TLS record, send it as-is
    if (total_record < len) {
        int sent3 = platform::send_data(fd, data + total_record, len - total_record);
        if (sent3 < 0) {
            return WriteResult::fail("tls_split: send trailing data failed");
        }
    }

    // Return original logical length (caller's perspective)
    return WriteResult::ok(static_cast<int>(len));
}

} // namespace tactics
} // namespace dpibypass
