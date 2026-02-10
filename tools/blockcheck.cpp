#include "dpibypass/auto_selector.h"
#include "dpibypass/dpibypass.h"
#include "dpibypass/tactics.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

void print_config(const TacticConfig& config) {
    uint32_t val = static_cast<uint32_t>(config.tactics);
    printf("  Tactics bitmask: 0x%02X\n", val);
    printf("  Active tactics:");

    const Tactic all_tactics[] = {
        Tactic::TcpSplit, Tactic::FakeRst, Tactic::FakeData,
        Tactic::Disorder, Tactic::OOB, Tactic::TlsRecordSplit,
    };

    bool any = false;
    for (auto t : all_tactics) {
        if (has_tactic(config.tactics, t)) {
            printf(" %s", tactic_name(t));
            any = true;
        }
    }
    if (!any) printf(" None");
    printf("\n");

    printf("  Split position: %d\n", config.split_position);
    printf("  Fake TTL: %d\n", config.fake_ttl);
}

// Known Telegram DC IPs (IPv4)
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
    printf("DPI bypass tactic checker for Telegram connections.\n\n");
    printf("Options:\n");
    printf("  -h, --help       Show this help\n");
    printf("  -t, --timeout N  Probe timeout in ms (default: 5000)\n");
    printf("  -a, --all        Test all DCs (default: DC2 only)\n");
    printf("  -H, --host HOST  Test specific host\n");
    printf("  -p, --port PORT  Test specific port (default: 443)\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    int timeout = 5000;
    bool test_all = false;
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
        if ((strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--host") == 0) && i + 1 < argc) {
            custom_host = argv[++i];
        }
        if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            custom_port = atoi(argv[++i]);
        }
    }

    printf("=== DPI Bypass Tactic Checker (blockcheck) ===\n\n");
    printf("Probe timeout: %d ms\n\n", timeout);

    auto candidates = AutoSelector::defaultCandidates();
    printf("Testing %zu tactic combinations:\n", candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        printf("  [%zu] ", i + 1);
        uint32_t val = static_cast<uint32_t>(candidates[i].tactics);
        const Tactic all_tactics[] = {
            Tactic::TcpSplit, Tactic::FakeRst, Tactic::FakeData,
            Tactic::Disorder, Tactic::OOB, Tactic::TlsRecordSplit,
        };
        for (auto t : all_tactics) {
            if (has_tactic(candidates[i].tactics, t)) {
                printf("%s ", tactic_name(t));
            }
        }
        if (val == 0) printf("None");
        printf("\n");
    }
    printf("\n");

    // Build list of endpoints to test
    struct Endpoint {
        std::string name;
        std::string host;
        int port;
    };

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
        printf("--- Testing %s (%s:%d) ---\n", ep.name.c_str(), ep.host.c_str(), ep.port);

        bool found = false;
        selector.probe(ep.host, ep.port, candidates,
                       [&](TacticConfig best) {
            if (best.tactics != Tactic::None) {
                printf("  SUCCESS! Working tactic found:\n");
                print_config(best);
                found = true;
            }
        });

        if (!found) {
            printf("  FAILED: No working tactic found.\n");
            printf("  Possible reasons:\n");
            printf("    - Host unreachable (check network)\n");
            printf("    - DPI not blocking this endpoint\n");
            printf("    - All tactics exhausted, need new approaches\n");
        }
        printf("\n");
    }

    printf("=== Done ===\n");
    return 0;
}
