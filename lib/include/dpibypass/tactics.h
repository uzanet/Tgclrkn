#pragma once

#include <cstdint>
#include <vector>

namespace dpibypass {

enum class Tactic : uint32_t {
    None           = 0,
    TcpSplit       = 1 << 0,
    FakeRst        = 1 << 1,
    FakeData       = 1 << 2,
    Disorder       = 1 << 3,
    OOB            = 1 << 4,
    TlsRecordSplit = 1 << 5,
};

inline Tactic operator|(Tactic a, Tactic b) {
    return static_cast<Tactic>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline Tactic operator&(Tactic a, Tactic b) {
    return static_cast<Tactic>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool has_tactic(Tactic set, Tactic flag) {
    return (static_cast<uint32_t>(set) & static_cast<uint32_t>(flag)) != 0;
}

enum class Protocol {
    Unknown,
    TLS,
    HTTP,
    MTProto,
};

struct TacticConfig {
    Tactic tactics = Tactic::None;
    int split_position = 3;
    std::vector<int> multi_split_positions;
    int fake_ttl = 1;
    int split_count = 2;
    uint8_t oob_byte = 0x00;
    int disorder_ttl = 1;
    size_t bypass_cutoff = 65536;

    static TacticConfig tcp_split_only(int pos = 3) {
        TacticConfig c;
        c.tactics = Tactic::TcpSplit;
        c.split_position = pos;
        return c;
    }

    static TacticConfig split_and_fake(int pos = 3, int ttl = 1) {
        TacticConfig c;
        c.tactics = Tactic::TcpSplit | Tactic::FakeRst;
        c.split_position = pos;
        c.fake_ttl = ttl;
        return c;
    }

    static TacticConfig split_and_disorder(int pos = 3) {
        TacticConfig c;
        c.tactics = Tactic::TcpSplit | Tactic::Disorder;
        c.split_position = pos;
        return c;
    }

    static TacticConfig full(int pos = 3) {
        TacticConfig c;
        c.tactics = Tactic::TcpSplit | Tactic::FakeData | Tactic::OOB;
        c.split_position = pos;
        return c;
    }
};

} // namespace dpibypass
