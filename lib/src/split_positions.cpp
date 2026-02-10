#include "tactics/tactic_base.h"

#include <cstring>
#include <algorithm>

namespace dpibypass {
namespace tactics {

namespace {

constexpr size_t TLS_RECORD_HEADER = 5;
constexpr size_t TLS_HANDSHAKE_HEADER = 4;
constexpr size_t TLS_CLIENT_HELLO_FIXED = 34;  // 2 version + 32 random

// Find the offset of the SNI extension within a TLS ClientHello
// Returns -1 if not found
int find_sni_offset(const uint8_t* data, size_t len) {
    // Minimum: record header(5) + handshake header(4) + fixed fields(34) + ...
    if (len < TLS_RECORD_HEADER + TLS_HANDSHAKE_HEADER + TLS_CLIENT_HELLO_FIXED + 3) {
        return -1;
    }

    // Verify this is a TLS Handshake record
    if (data[0] != 0x16) return -1;  // Not handshake content type

    // Verify this is a ClientHello
    if (data[TLS_RECORD_HEADER] != 0x01) return -1;

    size_t pos = TLS_RECORD_HEADER + TLS_HANDSHAKE_HEADER;

    // Skip client_version (2) + random (32)
    pos += TLS_CLIENT_HELLO_FIXED;
    if (pos >= len) return -1;

    // Skip session_id (1 byte length + data)
    uint8_t session_id_len = data[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > len) return -1;

    // Skip cipher_suites (2 byte length + data)
    uint16_t cs_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cs_len;
    if (pos + 1 > len) return -1;

    // Skip compression_methods (1 byte length + data)
    uint8_t cm_len = data[pos];
    pos += 1 + cm_len;
    if (pos + 2 > len) return -1;

    // Extensions length
    uint16_t ext_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;

    size_t ext_end = pos + ext_len;
    if (ext_end > len) ext_end = len;

    // Parse extensions looking for SNI (type 0x0000)
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        uint16_t ext_data_len = (static_cast<uint16_t>(data[pos + 2]) << 8) | data[pos + 3];

        if (ext_type == 0x0000) {
            // Found SNI extension — return its offset from the start
            return static_cast<int>(pos);
        }

        pos += 4 + ext_data_len;
    }

    return -1;
}

// Find "Host:" header offset in HTTP data
int find_host_header_offset(const uint8_t* data, size_t len) {
    const char* needle = "Host:";
    size_t needle_len = 5;

    for (size_t i = 0; i + needle_len <= len; ++i) {
        if (std::memcmp(data + i, needle, needle_len) == 0) {
            return static_cast<int>(i);
        }
        // Case-insensitive check
        if ((data[i] == 'H' || data[i] == 'h') &&
            (data[i+1] == 'O' || data[i+1] == 'o') &&
            (data[i+2] == 'S' || data[i+2] == 's') &&
            (data[i+3] == 'T' || data[i+3] == 't') &&
            data[i+4] == ':') {
            return static_cast<int>(i);
        }
    }
    return -1;
}

Protocol detect_protocol(const uint8_t* data, size_t len) {
    if (len < 3) return Protocol::Unknown;

    // TLS: starts with content type 0x14-0x18, version 0x03xx
    if (data[0] >= 0x14 && data[0] <= 0x18 && data[1] == 0x03) {
        return Protocol::TLS;
    }

    // HTTP: starts with a method
    if (len >= 4 && (
        std::memcmp(data, "GET ", 4) == 0 ||
        std::memcmp(data, "POST", 4) == 0 ||
        std::memcmp(data, "HEAD", 4) == 0 ||
        std::memcmp(data, "PUT ", 4) == 0)) {
        return Protocol::HTTP;
    }

    // MTProto: first 64 bytes are the obfuscated header
    // Hard to detect reliably — treat as unknown
    return Protocol::Unknown;
}

} // anonymous namespace

std::vector<int> calculate_split_positions(const uint8_t* data, size_t len,
                                           Protocol proto,
                                           const TacticConfig& config) {
    // If user specified explicit positions, use them
    if (!config.multi_split_positions.empty()) {
        return config.multi_split_positions;
    }

    // Auto-detect protocol if unknown
    if (proto == Protocol::Unknown) {
        proto = detect_protocol(data, len);
    }

    std::vector<int> positions;

    switch (proto) {
    case Protocol::TLS: {
        int sni_offset = find_sni_offset(data, len);
        if (sni_offset > 0) {
            // Split right before the SNI extension
            positions.push_back(sni_offset);
        } else {
            // Fallback: split after TLS record header + 1 byte
            positions.push_back(std::min(static_cast<int>(len),
                                         static_cast<int>(TLS_RECORD_HEADER) + 1));
        }
        break;
    }

    case Protocol::HTTP: {
        int host_offset = find_host_header_offset(data, len);
        if (host_offset > 0) {
            // Split in the middle of "Host:" header value
            positions.push_back(host_offset + 3);  // Split "Hos" | "t: value"
        } else {
            positions.push_back(config.split_position);
        }
        break;
    }

    case Protocol::MTProto:
        // Split after the first few bytes of the obfuscated header
        positions.push_back(std::min(config.split_position, static_cast<int>(len)));
        break;

    default:
        positions.push_back(std::min(config.split_position, static_cast<int>(len)));
        break;
    }

    return positions;
}

} // namespace tactics
} // namespace dpibypass
