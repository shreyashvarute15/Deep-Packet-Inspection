#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <fstream>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include "rule_manager.h"
#include "connection_tracker.h"

using namespace PacketAnalyzer;
using namespace DPI;

void printUsage(const char* prog) {
    std::cout << R"(
Packet Analyzer & DPI Engine (C++17)
=====================================
Usage: )" << prog << R"( [options]

Options:
  --pcap <file>          Path to input PCAP file (required)
  --output <file>        Save analysis output as JSON (optional)
  --block-ip <ip>        Add an IP block rule
  --block-app <app>      Add an App block rule (e.g. YouTube, Facebook)
  --block-domain <dom>   Add a Domain block rule (e.g. *.netflix.com)
  --threads <n>          Number of worker threads (default: 1)
  --help                 Show this help message
  --version              Show version information

Examples:
  )" << prog << R"( --pcap test_dpi.pcap
  )" << prog << R"( --pcap test_dpi.pcap --block-app YouTube --output report.json
)";
}

void printVersion() {
    std::cout << "Packet Analyzer & DPI Engine v2.0 (C++17)\n";
    std::cout << "Built with MSYS2 UCRT64 GCC\n";
}

int main(int argc, char* argv[]) {
    std::string pcap_file;
    std::string output_file;
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    int threads = 1;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--pcap" && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--version") {
            printVersion();
            return 0;
        }
    }

    if (pcap_file.empty()) {
        std::cerr << "Error: --pcap is required.\n";
        printUsage(argv[0]);
        return 1;
    }

    PcapReader reader;
    if (!reader.open(pcap_file)) {
        return 1;
    }

    RuleManager rules;
    for (const auto& ip : block_ips) rules.blockIP(ip);
    for (const auto& app_str : block_apps) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app_str) {
                rules.blockApp(static_cast<AppType>(i));
                break;
            }
        }
    }
    for (const auto& dom : block_domains) rules.blockDomain(dom);

    ConnectionTracker tracker(0);

    RawPacket raw;
    ParsedPacket parsed;

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    uint64_t tcp_count = 0;
    uint64_t udp_count = 0;

    std::unordered_map<AppType, uint64_t> app_stats;
    std::unordered_map<std::string, AppType> detected_snis;

    std::cout << "\n[DPI Engine] Analyzing " << pcap_file << "...\n";

    while (reader.readNextPacket(raw)) {
        total_packets++;
        total_bytes += raw.data.size();

        if (!PacketParser::parse(raw, parsed)) continue;

        if (parsed.has_tcp) tcp_count++;
        else if (parsed.has_udp) udp_count++;

        if (!parsed.has_ip) continue;

        // Five Tuple
        FiveTuple tuple;
        auto parseIP = [](const std::string& ip) -> uint32_t {
            uint32_t result = 0;
            int octet = 0, shift = 0;
            for (char c : ip) {
                if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
            }
            return result | (octet << shift);
        };

        tuple.src_ip = parseIP(parsed.src_ip);
        tuple.dst_ip = parseIP(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        Connection* conn = tracker.getOrCreateConnection(tuple);
        tracker.updateConnection(conn, raw.data.size(), true);

        // Classify if needed
        if (conn->state != ConnectionState::CLASSIFIED) {
            // Check TLS SNI
            if (parsed.has_tcp && parsed.dest_port == 443 && parsed.payload_length > 5) {
                auto sni = SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
                if (sni) {
                    tracker.classifyConnection(conn, sniToAppType(*sni), *sni);
                    detected_snis[*sni] = conn->app_type;
                }
            }
            // Check HTTP Host
            else if (parsed.has_tcp && parsed.dest_port == 80 && parsed.payload_length > 10) {
                auto host = HTTPHostExtractor::extract(parsed.payload_data, parsed.payload_length);
                if (host) {
                    tracker.classifyConnection(conn, sniToAppType(*host), *host);
                    detected_snis[*host] = conn->app_type;
                }
            }
            // Check DNS
            else if (parsed.has_udp && (parsed.src_port == 53 || parsed.dest_port == 53)) {
                if (parsed.payload_length > 12) {
                    auto query = DNSExtractor::extractQuery(parsed.payload_data, parsed.payload_length);
                    if (query) {
                        tracker.classifyConnection(conn, AppType::DNS, *query);
                        detected_snis[*query] = AppType::DNS;
                    } else {
                        tracker.classifyConnection(conn, AppType::DNS, "");
                    }
                }
            }
            // Fallbacks
            else if (parsed.dest_port == 443) {
                conn->app_type = AppType::HTTPS;
            } else if (parsed.dest_port == 80) {
                conn->app_type = AppType::HTTP;
            }
        }

        // Apply rules
        auto block_reason = rules.shouldBlock(tuple.src_ip, tuple.dst_port, conn->app_type, conn->sni);
        if (block_reason) {
            tracker.blockConnection(conn);
            dropped++;
        } else {
            forwarded++;
        }

        app_stats[conn->app_type]++;
    }

    reader.close();

    // Print CLI Report
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                      DPI ANALYSIS REPORT                     ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Total Packets:      " << std::setw(12) << total_packets << "                           ║\n";
    std::cout << "║ Total Bytes:        " << std::setw(12) << total_bytes << "                           ║\n";
    std::cout << "║ TCP Packets:        " << std::setw(12) << tcp_count << "                           ║\n";
    std::cout << "║ UDP Packets:        " << std::setw(12) << udp_count << "                           ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Forwarded Packets:  " << std::setw(12) << forwarded << "                           ║\n";
    std::cout << "║ Dropped Packets:    " << std::setw(12) << dropped << "                           ║\n";
    std::cout << "║ Total Connections:  " << std::setw(12) << tracker.getActiveCount() << "                           ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║                    APPLICATION BREAKDOWN                     ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";

    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (const auto& [app, count] : sorted_apps) {
        double pct = total_packets > 0 ? (100.0 * count / total_packets) : 0;
        int bar_len = static_cast<int>(pct / 5);
        std::string bar(bar_len, '#');
        std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                  << std::setw(8) << std::right << count
                  << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                  << std::setw(20) << std::left << bar << "  ║\n";
    }

    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

    if (!detected_snis.empty()) {
        std::cout << "\n[Detected Hostnames & DNS Queries]\n";
        for (const auto& [sni, app] : detected_snis) {
            std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
        }
    }

    // Save JSON if requested
    if (!output_file.empty()) {
        std::ofstream out(output_file);
        if (out.is_open()) {
            out << "{\n";
            out << "  \"total_packets\": " << total_packets << ",\n";
            out << "  \"total_bytes\": " << total_bytes << ",\n";
            out << "  \"tcp_packets\": " << tcp_count << ",\n";
            out << "  \"udp_packets\": " << udp_count << ",\n";
            out << "  \"forwarded\": " << forwarded << ",\n";
            out << "  \"dropped\": " << dropped << ",\n";
            out << "  \"connections\": " << tracker.getActiveCount() << ",\n";
            out << "  \"applications\": {\n";
            for (size_t i = 0; i < sorted_apps.size(); ++i) {
                out << "    \"" << appTypeToString(sorted_apps[i].first) << "\": " << sorted_apps[i].second;
                if (i + 1 < sorted_apps.size()) out << ",";
                out << "\n";
            }
            out << "  },\n";
            out << "  \"detected_hosts\": [\n";
            size_t idx = 0;
            for (const auto& [host, app] : detected_snis) {
                out << "    {\"host\": \"" << host << "\", \"app\": \"" << appTypeToString(app) << "\"}";
                if (++idx < detected_snis.size()) out << ",";
                out << "\n";
            }
            out << "  ]\n";
            out << "}\n";
            out.close();
            std::cout << "\n[Output] JSON report written to: " << output_file << "\n";
        }
    }

    return 0;
}
