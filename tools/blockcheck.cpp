#include "dpibypass/auto_selector.h"
#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

struct WinsockInit {
    WinsockInit() { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); }
    ~WinsockInit() { WSACleanup(); }
};
static WinsockInit _wsa;
#endif

using namespace dpibypass;

namespace {

const char* tactic_name(Tactic t) {
    switch (t) {
    case Tactic::None: return "None";
    case Tactic::TcpSplit: return "TcpSplit";
    case Tactic::FakeRst: return "FakeRst";
    case Tactic::FakeData: return "FakeData";
    case Tactic::Disorder: return "Disorder";
    case Tactic::OOB: return "OOB";
    case Tactic::TlsRecordSplit: return "TlsRecordSplit";
    default: return "Unknown";
    }
}

std::string tactics_str(const TacticConfig& config) {
    const Tactic all[] = {
        Tactic::TcpSplit, Tactic::FakeRst, Tactic::FakeData,
        Tactic::Disorder, Tactic::OOB, Tactic::TlsRecordSplit,
    };
    std::string result;
    for (auto t : all) {
        if (has_tactic(config.tactics, t)) {
            if (!result.empty()) result += "+";
            result += tactic_name(t);
        }
    }
    if (result.empty()) result = "None";
    return result;
}

void print_config(const TacticConfig& config) {
    printf("  Tactics: %s\n", tactics_str(config).c_str());
    printf("  Split position: %d\n", config.split_position);
    if (has_tactic(config.tactics, Tactic::FakeRst) || has_tactic(config.tactics, Tactic::FakeData)) {
        printf("  Fake TTL: %d\n", config.fake_ttl);
    }
}

struct DCInfo {
    const char* name;
    const char* ip;
    int port;
};

const DCInfo telegram_dcs[] = {
    {"DC1", "149.154.175.50", 443},
    {"DC2", "149.154.167.50", 443},
    {"DC3", "149.154.175.100", 443},
    {"DC4", "149.154.167.91", 443},
    {"DC5", "91.108.56.100", 443},
    {"DC2 (web)", "149.154.167.99", 443},
};

} // anonymous namespace

void print_usage(const char* prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("DPI bypass tactic checker for Telegram connections.\n");
    printf("Tests each DPI bypass tactic and shows detailed diagnostics.\n\n");
    printf("Options:\n");
    printf("  -h, --help       Show this help\n");
    printf("  -t, --timeout N  Probe timeout in ms (default: 5000)\n");
    printf("  -a, --all        Test all DCs (default: DC2 only)\n");
    printf("  -v, --verbose    Show details for each tactic probe\n");
    printf("  -H, --host HOST  Test specific host\n");
    printf("  -p, --port PORT  Test specific port (default: 443)\n");
    printf("  -d, --direct     Also test direct connection (no DPI bypass)\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    int timeout = 5000;
    bool test_all = false;
    bool verbose = false;
    bool test_direct = false;
    std::string custom_host;
    int custom_port = 443;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) && i + 1 < argc) {
            timeout = atoi(argv[++i]);
        }
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            test_all = true;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--direct") == 0) {
            test_direct = true;
        }
        if ((strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--host") == 0) && i + 1 < argc) {
            custom_host = argv[++i];
        }
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            custom_port = atoi(argv[++i]);
        }
    }

    printf("=== DPI Bypass Tactic Checker (blockcheck) ===\n\n");
    printf("Probe timeout: %d ms\n\n", timeout);

    // Build candidate list
    std::vector<TacticConfig> candidates;
    if (test_direct) {
        TacticConfig direct;
        direct.tactics = Tactic::None;
        candidates.push_back(direct);
    }
    auto defaults = AutoSelector::defaultCandidates();
    candidates.insert(candidates.end(), defaults.begin(), defaults.end());

    printf("Probing %zu tactic combinations:\n", candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        printf("  [%zu] %s (split=%d)\n", i + 1,
               tactics_str(candidates[i]).c_str(),
               candidates[i].split_position);
    }
    printf("\n");

    // Build endpoints
    struct Endpoint { std::string name; std::string host; int port; };
    std::vector<Endpoint> endpoints;
    if (!custom_host.empty()) {
        endpoints.push_back({custom_host, custom_host, custom_port});
    } else if (test_all) {
        for (const auto& dc : telegram_dcs) {
            endpoints.push_back({dc.name, dc.ip, dc.port});
        }
    } else {
        endpoints.push_back({telegram_dcs[1].name, telegram_dcs[1].ip, telegram_dcs[1].port});
    }

    AutoSelector selector;
    selector.setProbeTimeout(timeout);

    for (const auto& ep : endpoints) {
        printf("--- %s (%s:%d) ---\n", ep.name.c_str(), ep.host.c_str(), ep.port);

        bool any_success = false;

        for (size_t i = 0; i < candidates.size(); ++i) {
            const auto& config = candidates[i];
            std::string name = tactics_str(config);

            if (verbose) {
                printf("  [%zu] Testing %s... ", i + 1, name.c_str());
                fflush(stdout);
            }

            ProbeResult result = selector.probeSingle(ep.host, ep.port, config);

            if (result.success) {
                if (verbose) {
                    printf("OK (%dms)", result.latency_ms);
                    if (!result.error.empty()) printf(" [%s]", result.error.c_str());
                    printf("\n");
                } else {
                    printf("  [OK] %s (%dms)\n", name.c_str(), result.latency_ms);
                }
                if (!any_success) {
                    printf("\n  >>> Best working tactic: %s <<<\n", name.c_str());
                    print_config(config);
                    any_success = true;
                }
                if (!verbose) break;  // In non-verbose mode, stop at first success
            } else {
                if (verbose) {
                    printf("FAIL - %s\n", result.error.c_str());
                } else {
                    printf("  [--] %s: %s\n", name.c_str(), result.error.c_str());
                }
            }
        }

        if (!any_success) {
            printf("\n  >>> No working tactic found <<<\n");
            printf("  Diagnostics:\n");
            // Run one more probe with None to check basic connectivity
            TacticConfig none;
            none.tactics = Tactic::None;
            ProbeResult direct = selector.probeSingle(ep.host, ep.port, none);
            if (direct.success) {
                printf("    - Direct connection works! DPI is NOT blocking this endpoint.\n");
                printf("    - No DPI bypass needed for %s\n", ep.host.c_str());
            } else if (direct.error.find("TCP connect") != std::string::npos) {
                printf("    - TCP connection failed: %s\n", direct.error.c_str());
                printf("    - The host may be IP-blocked (not just DPI).\n");
                printf("    - DPI bypass cannot help with IP-level blocks.\n");
                printf("    - You may need a proxy/VPN instead.\n");
            } else if (direct.error.find("reset") != std::string::npos) {
                printf("    - Connection was reset (RST). This looks like DPI blocking.\n");
                printf("    - But none of our tactics worked. Try:\n");
                printf("      * Increasing timeout: blockcheck -t 10000\n");
                printf("      * Different split positions may be needed\n");
            } else {
                printf("    - Direct probe result: %s\n", direct.error.c_str());
            }
        }
        printf("\n");
    }

    printf("=== Done ===\n");
    return 0;
}
