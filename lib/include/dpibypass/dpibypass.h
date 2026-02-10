#pragma once

#include "dpibypass/tactics.h"
#include "dpibypass/socket_wrapper.h"

#include <string>
#include <memory>
#include <functional>

namespace dpibypass {

struct WriteResult {
    bool success = false;
    int bytes_written = 0;
    std::string error;

    static WriteResult ok(int n) { return {true, n, {}}; }
    static WriteResult fail(const std::string& err) { return {false, 0, err}; }
};

class BypassSocket {
public:
    explicit BypassSocket(socket_t fd);
    ~BypassSocket() = default;

    BypassSocket(const BypassSocket&) = delete;
    BypassSocket& operator=(const BypassSocket&) = delete;

    void setConfig(const TacticConfig& config);
    const TacticConfig& config() const { return config_; }

    WriteResult writeWithBypass(const uint8_t* data, size_t len);

    int write(const uint8_t* data, size_t len);

    void onConnected();
    void reset();

    socket_t fd() const { return fd_; }
    bool bypassActive() const { return !first_write_done_ || bytes_sent_ < config_.bypass_cutoff; }

private:
    WriteResult applyTactics(const uint8_t* data, size_t len);

    socket_t fd_;
    TacticConfig config_;
    bool first_write_done_ = false;
    size_t bytes_sent_ = 0;
};

} // namespace dpibypass
