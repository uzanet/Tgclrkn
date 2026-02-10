#include "tactic_base.h"
#include "dpibypass/socket_wrapper.h"

namespace dpibypass {
namespace tactics {

WriteResult oob_write(socket_t fd, const uint8_t* data, size_t len,
                      const TacticConfig& config) {
    // OOB (Out-Of-Band) strategy:
    //
    // TCP urgent data mechanism allows sending a single "urgent" byte
    // that is delivered out-of-band. DPI systems that reassemble the
    // TCP stream may incorrectly include the OOB byte in the data,
    // seeing corrupted content. The server's TCP stack handles OOB
    // separately via the urgent pointer.
    //
    // Approach:
    // 1. Send first part of data (up to split_position)
    // 2. Send OOB byte using MSG_OOB flag
    // 3. Send remaining data
    //
    // The OOB byte appears in-band to naive DPI but is extracted
    // by the server's TCP stack, resulting in clean data.

    int split_pos = config.split_position;
    if (split_pos <= 0 || static_cast<size_t>(split_pos) >= len) {
        int sent = platform::send_data(fd, data, len);
        if (sent < 0) return WriteResult::fail("oob: send failed");
        return WriteResult::ok(sent);
    }

    platform::set_tcp_nodelay(fd, true);

    // Send first segment
    int sent1 = platform::send_data(fd, data, static_cast<size_t>(split_pos));
    if (sent1 < 0) {
        return WriteResult::fail("oob: send first segment failed");
    }

    // Send OOB byte
    uint8_t oob = config.oob_byte;
    int oob_sent = platform::send_oob(fd, &oob, 1);
    if (oob_sent < 0) {
        return WriteResult::fail("oob: send OOB byte failed");
    }

    // Send remaining data
    size_t remaining = len - static_cast<size_t>(split_pos);
    int sent2 = platform::send_data(fd, data + split_pos, remaining);
    if (sent2 < 0) {
        return WriteResult::fail("oob: send remaining data failed");
    }

    return WriteResult::ok(sent1 + sent2);
}

} // namespace tactics
} // namespace dpibypass
