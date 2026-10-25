#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// Map a hostname/SNI to an application using DNS-label boundaries.
// Avoid substring checks such as "x.com" matching "netflix.com" or
// "t.co" matching "microsoft.com".
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    std::string host = sni;
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // HTTP Host values may include a port; DNS/SNI hostnames may have a final dot.
    const auto colon = host.find(':');
    if (colon != std::string::npos) host.erase(colon);
    while (!host.empty() && host.back() == '.') host.pop_back();
    if (host.empty()) return AppType::UNKNOWN;

    const auto isDomainOrSubdomain = [&host](const char* domain) {
        const std::string suffix(domain);
        if (host == suffix) return true;
        return host.size() > suffix.size() &&
               host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0 &&
               host[host.size() - suffix.size() - 1] == '.';
    };
    const auto matchesAny = [&isDomainOrSubdomain](std::initializer_list<const char*> domains) {
        for (const char* domain : domains) {
            if (isDomainOrSubdomain(domain)) return true;
        }
        return false;
    };

    // Order specific service domains before broader parent-company domains.
    if (matchesAny({"youtube.com", "youtube-nocookie.com", "youtu.be", "ytimg.com",
                    "googlevideo.com"})) {
        return AppType::YOUTUBE;
    }
    if (matchesAny({"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
                    "ggpht.com", "gvt1.com"})) {
        return AppType::GOOGLE;
    }
    if (matchesAny({"facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com"})) {
        return AppType::FACEBOOK;
    }
    if (matchesAny({"instagram.com", "cdninstagram.com"})) {
        return AppType::INSTAGRAM;
    }
    if (matchesAny({"whatsapp.com", "whatsapp.net", "wa.me"})) {
        return AppType::WHATSAPP;
    }
    if (matchesAny({"twitter.com", "twimg.com", "x.com", "t.co"})) {
        return AppType::TWITTER;
    }
    if (matchesAny({"netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net",
                    "nflxext.com"})) {
        return AppType::NETFLIX;
    }
    if (matchesAny({"amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.in",
                    "amazon.de", "cloudfront.net"})) {
        return AppType::AMAZON;
    }
    if (matchesAny({"microsoft.com", "msn.com", "office.com", "office365.com", "azure.com",
                    "live.com", "outlook.com", "bing.com", "microsoftonline.com",
                    "windows.net", "sharepoint.com", "skype.com"})) {
        return AppType::MICROSOFT;
    }
    if (matchesAny({"apple.com", "icloud.com", "mzstatic.com", "itunes.com"})) {
        return AppType::APPLE;
    }
    if (matchesAny({"telegram.org", "t.me"})) {
        return AppType::TELEGRAM;
    }
    if (matchesAny({"tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com"})) {
        return AppType::TIKTOK;
    }
    if (matchesAny({"spotify.com", "scdn.co"})) {
        return AppType::SPOTIFY;
    }
    if (matchesAny({"zoom.us", "zoom.com"})) {
        return AppType::ZOOM;
    }
    if (matchesAny({"discord.com", "discord.gg", "discordapp.com"})) {
        return AppType::DISCORD;
    }
    if (matchesAny({"github.com", "githubusercontent.com"})) {
        return AppType::GITHUB;
    }
    if (matchesAny({"cloudflare.com", "cloudflare-dns.com"})) {
        return AppType::CLOUDFLARE;
    }

    // An unrecognized hostname can still identify TLS/HTTPS traffic.
    return AppType::HTTPS;
}
} // namespace DPI
