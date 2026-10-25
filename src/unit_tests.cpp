#include <iostream>
#include <cassert>
#include <vector>
#include "sni_extractor.h"
#include "types.h"
#include "rule_manager.h"

using namespace DPI;

void test_tls_sni_extraction() {
    std::cout << "[Test] Running test_tls_sni_extraction...\n";
    // Construct a synthetic minimal TLS ClientHello with SNI
    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x2b, // Record Header (len 43)
        0x01, 0x00, 0x00, 0x27,       // Handshake ClientHello (len 39)
        0x03, 0x03,                   // TLS 1.2
    };
    // 32 random bytes
    for (int i = 0; i < 32; ++i) payload.push_back(0x00);
    payload.push_back(0x00); // Session ID len 0
    payload.push_back(0x00); payload.push_back(0x00); // Cipher suites len 0
    payload.push_back(0x00); // Compression len 0

    // Extensions len: 14 bytes
    payload.push_back(0x00); payload.push_back(0x0e);
    // Extension: Server Name (0x0000), len 10
    payload.push_back(0x00); payload.push_back(0x00);
    payload.push_back(0x00); payload.push_back(0x0a);
    // SNI list len 8
    payload.push_back(0x00); payload.push_back(0x08);
    // Type Hostname (0x00), len 5
    payload.push_back(0x00); payload.push_back(0x00); payload.push_back(0x05);
    // Hostname: "apple"
    payload.push_back('a'); payload.push_back('p'); payload.push_back('p');
    payload.push_back('l'); payload.push_back('e');

    // Update length bytes
    uint16_t total_handshake = payload.size() - 5;
    payload[3] = (total_handshake >> 8) & 0xFF;
    payload[4] = total_handshake & 0xFF;

    auto sni = SNIExtractor::extract(payload.data(), payload.size());
    assert(sni.has_value());
    assert(*sni == "apple");
    std::cout << "  -> PASSED: Successfully extracted SNI: " << *sni << "\n";
}

void test_http_host_extraction() {
    std::cout << "[Test] Running test_http_host_extraction...\n";
    std::string http_req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    auto host = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(http_req.data()), http_req.size());
    assert(host.has_value());
    assert(*host == "example.com");
    std::cout << "  -> PASSED: Successfully extracted Host: " << *host << "\n";
}

void test_dns_query_extraction() {
    std::cout << "[Test] Running test_dns_query_extraction...\n";
    std::vector<uint8_t> dns_query = {
        0x12, 0x34, // TxID
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Query: 6 google 3 com 0
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, // Type A
        0x00, 0x01  // Class IN
    };

    auto domain = DNSExtractor::extractQuery(dns_query.data(), dns_query.size());
    assert(domain.has_value());
    assert(*domain == "google.com");
    std::cout << "  -> PASSED: Successfully extracted DNS domain: " << *domain << "\n";
}


void test_application_classification() {
    std::cout << "[Test] Running test_application_classification...\n";
    assert(sniToAppType("www.microsoft.com") == AppType::MICROSOFT);
    assert(sniToAppType("www.netflix.com") == AppType::NETFLIX);
    assert(sniToAppType("api.twitter.com") == AppType::TWITTER);
    assert(sniToAppType("x.com") == AppType::TWITTER);
    assert(sniToAppType("sub.example.net") == AppType::HTTPS);
    assert(sniToAppType("microsoft.com.evil.example") == AppType::HTTPS);
    assert(sniToAppType("netflix.com.evil.example") == AppType::HTTPS);
    assert(sniToAppType("www.microsoft.com:443") == AppType::MICROSOFT);
    std::cout << "  -> PASSED: Domain-boundary application classification verified.\n";
}

void test_rule_manager() {
    std::cout << "[Test] Running test_rule_manager...\n";
    RuleManager rm;
    rm.blockIP("192.168.1.100");
    rm.blockDomain("*.badsite.com");
    rm.blockApp(AppType::YOUTUBE);

    auto blocked_ips = rm.getBlockedIPs();
    assert(blocked_ips.size() == 1);
    assert(blocked_ips[0] == "192.168.1.100");

    assert(rm.isDomainBlocked("test.badsite.com"));
    assert(!rm.isDomainBlocked("goodsite.com"));

    assert(rm.isAppBlocked(AppType::YOUTUBE));
    assert(!rm.isAppBlocked(AppType::GOOGLE));
    std::cout << "  -> PASSED: All RuleManager policies verified.\n";
}

int main() {
    std::cout << "=== RUNNING UNIT & INTEGRATION TESTS ===\n";
    test_tls_sni_extraction();
    test_http_host_extraction();
    test_dns_query_extraction();
    test_application_classification();
    test_rule_manager();
    std::cout << "=== ALL TESTS COMPLETED SUCCESSFULLY! ===\n";
    return 0;
}
