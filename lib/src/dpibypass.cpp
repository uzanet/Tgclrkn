#include "dpibypass/dpibypass.h"
#include "tactics/tactic_base.h"

namespace dpibypass {

BypassSocket::BypassSocket(socket_t fd)
    : fd_(fd)
    , config_{}
{
}

void BypassSocket::setConfig(const TacticConfig& config) {
    config_ = config;
}

void BypassSocket::onConnected() {
    first_write_done_ = false;
    bytes_sent_ = 0;
}

void BypassSocket::reset() {
    first_write_done_ = false;
    bytes_sent_ = 0;
}

int BypassSocket::write(const uint8_t* data, size_t len) {
    return platform::send_data(fd_, data, len);
}

WriteResult BypassSocket::writeWithBypass(const uint8_t* data, size_t len) {
    if (config_.tactics == Tactic::None) {
        int sent = write(data, len);
        if (sent < 0) return WriteResult::fail("plain send failed");
        bytes_sent_ += sent;
        return WriteResult::ok(sent);
    }

    if (bytes_sent_ >= config_.bypass_cutoff) {
        int sent = write(data, len);
        if (sent < 0) return WriteResult::fail("passthrough send failed");
        bytes_sent_ += sent;
        return WriteResult::ok(sent);
    }

    WriteResult result = applyTactics(data, len);
    if (result.success) {
        bytes_sent_ += result.bytes_written;
        first_write_done_ = true;
    }
    return result;
}

WriteResult BypassSocket::applyTactics(const uint8_t* data, size_t len) {
    // Detect protocol and calculate optimal split positions
    auto positions = tactics::calculate_split_positions(
        data, len, Protocol::Unknown, config_);

    // Update config with auto-detected positions if none were set
    TacticConfig effective = config_;
    if (effective.multi_split_positions.empty() && !positions.empty()) {
        effective.multi_split_positions = positions;
        if (!positions.empty()) {
            effective.split_position = positions[0];
        }
    }

    // Apply TLS record split first (rewrites data at application layer)
    // This must happen before TCP-level tactics
    if (has_tactic(effective.tactics, Tactic::TlsRecordSplit)) {
        return tactics::tls_record_split_write(fd_, data, len, effective);
    }

    // Fake packets go before real data
    if (has_tactic(effective.tactics, Tactic::FakeRst)) {
        // Send fake RST with low TTL, then proceed with real data tactics
        int orig_ttl = platform::get_ttl(fd_);
        if (orig_ttl <= 0) orig_ttl = 64;

        platform::set_ttl(fd_, effective.fake_ttl);

        // Send a small fake payload
        uint8_t fake[] = {0x16, 0x03, 0x01, 0x00, 0x01, 0x01};
        platform::send_data(fd_, fake, sizeof(fake));

        platform::set_ttl(fd_, orig_ttl);
    }

    if (has_tactic(effective.tactics, Tactic::FakeData)) {
        return tactics::fake_data_write(fd_, data, len, effective);
    }

    // Disorder: send segments in wrong order
    if (has_tactic(effective.tactics, Tactic::Disorder)) {
        return tactics::disorder_write(fd_, data, len, effective);
    }

    // OOB: inject out-of-band byte
    if (has_tactic(effective.tactics, Tactic::OOB)) {
        return tactics::oob_write(fd_, data, len, effective);
    }

    // TCP split: default fallback if no other tactic consumed the data
    if (has_tactic(effective.tactics, Tactic::TcpSplit)) {
        return tactics::tcp_split_write(fd_, data, len, effective);
    }

    // No applicable tactic — send normally
    int sent = platform::send_data(fd_, data, len);
    if (sent < 0) return WriteResult::fail("send failed");
    return WriteResult::ok(sent);
}

} // namespace dpibypass
