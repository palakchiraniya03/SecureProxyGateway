#include "authenticator.h"

#include <cctype>
#include <cstdint>
#include <utility>

namespace {

std::string_view trim_whitespace(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool constant_time_equals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace

Authenticator::Authenticator(std::string username, std::string password)
    : username_(std::move(username)), password_(std::move(password)) {}

bool Authenticator::base64_decode(std::string_view in, std::string& out) {
    out.clear();

    std::string clean;
    clean.reserve(in.size());
    for (char c : in) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean.push_back(c);
        }
    }

    if (clean.empty()) {
        return true;
    }

    if (clean.size() % 4 != 0) {
        return false;
    }

    out.reserve((clean.size() / 4) * 3);

    auto b64_val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    for (size_t i = 0; i < clean.size(); i += 4) {
        char c0 = clean[i];
        char c1 = clean[i + 1];
        char c2 = clean[i + 2];
        char c3 = clean[i + 3];

        int v0 = b64_val(c0);
        int v1 = b64_val(c1);
        if (v0 < 0 || v1 < 0) {
            return false;
        }

        uint32_t triple = (static_cast<uint32_t>(v0) << 18) |
                          (static_cast<uint32_t>(v1) << 12);

        if (c2 == '=') {
            if (c3 != '=' || i + 4 != clean.size()) {
                return false;
            }
            out.push_back(static_cast<char>((triple >> 16) & 0xFF));
            break;
        }

        int v2 = b64_val(c2);
        if (v2 < 0) {
            return false;
        }
        triple |= (static_cast<uint32_t>(v2) << 6);

        if (c3 == '=') {
            if (i + 4 != clean.size()) {
                return false;
            }
            out.push_back(static_cast<char>((triple >> 16) & 0xFF));
            out.push_back(static_cast<char>((triple >> 8) & 0xFF));
            break;
        }

        int v3 = b64_val(c3);
        if (v3 < 0) {
            return false;
        }
        triple |= static_cast<uint32_t>(v3);

        out.push_back(static_cast<char>((triple >> 16) & 0xFF));
        out.push_back(static_cast<char>((triple >> 8) & 0xFF));
        out.push_back(static_cast<char>(triple & 0xFF));
    }

    return true;
}

std::string Authenticator::base64_encode(std::string_view in) {
    static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < in.size()) {
        size_t remaining = in.size() - i;
        uint32_t b0 = static_cast<uint8_t>(in[i++]);
        uint32_t b1 = (remaining > 1) ? static_cast<uint8_t>(in[i++]) : 0;
        uint32_t b2 = (remaining > 2) ? static_cast<uint8_t>(in[i++]) : 0;

        uint32_t triple = (b0 << 16) | (b1 << 8) | b2;

        out.push_back(kTable[(triple >> 18) & 0x3F]);
        out.push_back(kTable[(triple >> 12) & 0x3F]);
        out.push_back((remaining > 1) ? kTable[(triple >> 6) & 0x3F] : '=');
        out.push_back((remaining > 2) ? kTable[triple & 0x3F] : '=');
    }
    return out;
}

bool Authenticator::authenticate(std::string_view auth_header) const {
    std::string_view trimmed = trim_whitespace(auth_header);
    if (trimmed.size() < 6) {
        return false;
    }

    if (!iequals(trimmed.substr(0, 6), "Basic ")) {
        return false;
    }

    std::string_view b64_payload = trim_whitespace(trimmed.substr(6));
    if (b64_payload.empty()) {
        return false;
    }

    std::string decoded;
    if (!base64_decode(b64_payload, decoded)) {
        return false;
    }

    size_t colon_pos = decoded.find(':');
    if (colon_pos == std::string::npos) {
        return false;
    }

    std::string user = decoded.substr(0, colon_pos);
    std::string pass = decoded.substr(colon_pos + 1);

    bool user_ok = constant_time_equals(user, username_);
    bool pass_ok = constant_time_equals(pass, password_);

    return (user_ok && pass_ok);
}

std::string Authenticator::make_407_response() {
    const std::string body = "Proxy Authentication Required.\n";
    return "HTTP/1.1 407 Proxy Authentication Required\r\n"
           "Proxy-Authenticate: Basic realm=\"" + std::string(REALM) + "\"\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}
