#include "http_parser.h"

#include <cctype>
#include <optional>
#include <vector>
#include <arpa/inet.h>

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

std::string to_lower_str(std::string_view sv) {
    std::string res;
    res.reserve(sv.size());
    for (char c : sv) {
        res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return res;
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

bool parse_port(std::string_view port_str, uint16_t& out_port) {
    if (port_str.empty()) {
        return false;
    }
    uint32_t val = 0;
    for (char c : port_str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
        val = val * 10 + static_cast<uint32_t>(c - '0');
        if (val > 65535) {
            return false;
        }
    }
    if (val == 0) {
        return false;
    }
    out_port = static_cast<uint16_t>(val);
    return true;
}

bool is_valid_hostname_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) ||
           c == '.' || c == '-' || c == '_';
}

std::string normalize_hostname(std::string_view h) {
    std::string s = to_lower_str(h);
    while (!s.empty() && s.back() == '.') {
        s.pop_back();
    }
    return s;
}

// Parses host and optional port from an authority string (e.g. "example.com:8080", "example.com", "[::1]:8080")
bool parse_authority(std::string_view authority, std::string& out_host, std::optional<uint16_t>& out_port, std::string& error_msg) {
    if (authority.empty()) {
        error_msg = "Authority/host cannot be empty";
        return false;
    }

    if (authority.front() == '[') {
        size_t closing = authority.find(']');
        if (closing == std::string_view::npos) {
            error_msg = "Malformed IPv6 address (missing closing bracket)";
            return false;
        }
        std::string_view raw_ipv6 = authority.substr(1, closing - 1);
        if (raw_ipv6.empty()) {
            error_msg = "IPv6 literal cannot be empty";
            return false;
        }

        std::string ipv6_str(raw_ipv6);
        struct in6_addr addr6{};
        if (inet_pton(AF_INET6, ipv6_str.c_str(), &addr6) != 1) {
            error_msg = "Invalid IPv6 address literal: " + ipv6_str;
            return false;
        }

        out_host = to_lower_str(raw_ipv6);

        std::string_view remainder = authority.substr(closing + 1);
        if (remainder.empty()) {
            out_port = std::nullopt;
            return true;
        }
        if (remainder.front() == ':') {
            std::string_view port_str = remainder.substr(1);
            uint16_t port_val = 0;
            if (!parse_port(port_str, port_val)) {
                error_msg = "Invalid port in IPv6 authority: " + std::string(port_str);
                return false;
            }
            out_port = port_val;
            return true;
        }
        error_msg = "Unexpected characters after IPv6 closing bracket: " + std::string(remainder);
        return false;
    }

    std::string_view host_part;
    std::optional<uint16_t> port_val;

    size_t colon_pos = authority.find(':');
    if (colon_pos != std::string_view::npos) {
        host_part = authority.substr(0, colon_pos);
        std::string_view port_str = authority.substr(colon_pos + 1);

        if (host_part.empty()) {
            error_msg = "Host part cannot be empty in authority";
            return false;
        }
        uint16_t p = 0;
        if (!parse_port(port_str, p)) {
            error_msg = "Invalid port in authority: " + std::string(port_str);
            return false;
        }
        port_val = p;
    } else {
        host_part = authority;
    }

    if (host_part.empty()) {
        error_msg = "Host part cannot be empty";
        return false;
    }

    for (char c : host_part) {
        if (!is_valid_hostname_char(c)) {
            error_msg = "Invalid character in host: '" + std::string(1, c) + "'";
            return false;
        }
    }

    std::string norm = normalize_hostname(host_part);
    if (norm.empty()) {
        error_msg = "Host cannot be empty after stripping trailing dot";
        return false;
    }

    out_host = norm;
    out_port = port_val;
    return true;
}

} // namespace

HttpRequest HttpParser::parse(std::string_view raw_request) {
    HttpRequest req;
    req.status = ParseStatus::Incomplete;
    req.valid = false;

    // Unambiguous CRLF-based header termination
    size_t header_end_pos = raw_request.find("\r\n\r\n");
    if (header_end_pos == std::string_view::npos) {
        if (raw_request.size() > MAX_HEADER_BLOCK_SIZE) {
            req.status = ParseStatus::Error;
            req.error_message = "Header block exceeds maximum size of 8 KB";
            return req;
        }
        req.status = ParseStatus::Incomplete;
        req.error_message = "Incomplete request: header terminator not received";
        return req;
    }

    constexpr size_t terminator_len = 4;
    if (header_end_pos + terminator_len > MAX_HEADER_BLOCK_SIZE) {
        req.status = ParseStatus::Error;
        req.error_message = "Header block exceeds maximum size of 8 KB";
        return req;
    }

    req.header_length = header_end_pos + terminator_len;
    std::string_view header_block = raw_request.substr(0, header_end_pos);

    // Reject control characters (< 0x20 except CR, LF, HTAB, and reject DEL 0x7F)
    for (char c : header_block) {
        unsigned char uc = static_cast<unsigned char>(c);
        if ((uc < 0x20 && uc != '\r' && uc != '\n' && uc != '\t') || uc == 0x7F) {
            req.status = ParseStatus::Error;
            req.error_message = "Invalid control character in request";
            return req;
        }
    }

    // Split header block into lines delimited by CRLF
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start < header_block.size()) {
        size_t end = header_block.find("\r\n", start);
        if (end == std::string_view::npos) {
            lines.push_back(header_block.substr(start));
            break;
        }
        lines.push_back(header_block.substr(start, end - start));
        start = end + 2;
    }

    if (lines.empty()) {
        req.status = ParseStatus::Error;
        req.error_message = "Empty request line";
        return req;
    }

    std::string_view request_line = lines[0];
    if (request_line.empty()) {
        req.status = ParseStatus::Error;
        req.error_message = "Empty request line";
        return req;
    }

    // Disallow tabs in request line
    for (char c : request_line) {
        if (c == '\t') {
            req.status = ParseStatus::Error;
            req.error_message = "Tab not allowed in request line";
            return req;
        }
    }

    // Split request line by space
    std::vector<std::string_view> request_line_parts;
    size_t token_start = 0;
    while (token_start < request_line.size()) {
        size_t space_pos = request_line.find(' ', token_start);
        if (space_pos == std::string_view::npos) {
            request_line_parts.push_back(request_line.substr(token_start));
            break;
        }
        request_line_parts.push_back(request_line.substr(token_start, space_pos - token_start));
        token_start = space_pos + 1;
    }

    if (request_line_parts.size() != 3) {
        req.status = ParseStatus::Error;
        req.error_message = "Malformed request line: expected 3 tokens (Method, Target, Version)";
        return req;
    }

    req.method = std::string(request_line_parts[0]);
    req.request_target = std::string(request_line_parts[1]);
    req.version = std::string(request_line_parts[2]);

    if (req.method.empty()) {
        req.status = ParseStatus::Error;
        req.error_message = "Empty HTTP method";
        return req;
    }

    for (char c : req.method) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
            req.status = ParseStatus::Error;
            req.error_message = "Invalid characters in HTTP method";
            return req;
        }
    }

    if (req.request_target.empty()) {
        req.status = ParseStatus::Error;
        req.error_message = "Empty request target";
        return req;
    }

    // Accept only HTTP/1.0 and HTTP/1.1
    if (req.version != "HTTP/1.0" && req.version != "HTTP/1.1") {
        req.status = ParseStatus::Error;
        req.error_message = "Unsupported or invalid HTTP version: " + req.version;
        return req;
    }

    // Parse header fields; an empty line inside header block marks the end of headers
    bool host_seen = false;
    bool content_length_seen = false;

    for (size_t i = 1; i < lines.size(); ++i) {
        std::string_view line = lines[i];
        if (line.empty()) {
            break;
        }

        size_t colon_pos = line.find(':');
        if (colon_pos == std::string_view::npos) {
            req.status = ParseStatus::Error;
            req.error_message = "Malformed header line (missing colon): " + std::string(line);
            return req;
        }

        std::string_view header_name = line.substr(0, colon_pos);
        if (!header_name.empty() && (header_name.back() == ' ' || header_name.back() == '\t')) {
            req.status = ParseStatus::Error;
            req.error_message = "Whitespace not allowed before colon in header name";
            return req;
        }

        std::string_view header_value = trim_whitespace(line.substr(colon_pos + 1));

        if (iequals(header_name, "Host")) {
            if (host_seen) {
                req.status = ParseStatus::Error;
                req.error_message = "Duplicate Host header";
                return req;
            }
            host_seen = true;
            req.host_header = std::string(header_value);
        } else if (iequals(header_name, "Transfer-Encoding")) {
            req.status = ParseStatus::Error;
            req.error_message = "Transfer-Encoding header is not supported";
            return req;
        } else if (iequals(header_name, "Proxy-Authorization")) {
            req.proxy_authorization = std::string(header_value);
        } else if (iequals(header_name, "Content-Length")) {
            if (content_length_seen) {
                req.status = ParseStatus::Error;
                req.error_message = "Duplicate Content-Length header";
                return req;
            }
            content_length_seen = true;

            if (header_value.empty()) {
                req.status = ParseStatus::Error;
                req.error_message = "Content-Length header cannot be empty";
                return req;
            }
            uint64_t cl_val = 0;
            for (char c : header_value) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    req.status = ParseStatus::Error;
                    req.error_message = "Invalid non-numeric Content-Length: " + std::string(header_value);
                    return req;
                }
                cl_val = cl_val * 10 + static_cast<uint64_t>(c - '0');
                if (cl_val > 1000000000000ULL) {
                    req.status = ParseStatus::Error;
                    req.error_message = "Content-Length exceeds maximum allowable size";
                    return req;
                }
            }
            req.content_length = static_cast<size_t>(cl_val);
        }
    }

    // CONNECT method handling: authority-form target (host:port)
    if (req.method == "CONNECT") {
        std::string connect_host;
        std::optional<uint16_t> connect_port;
        std::string auth_err;
        if (!parse_authority(req.request_target, connect_host, connect_port, auth_err)) {
            req.status = ParseStatus::Error;
            req.error_message = "Invalid CONNECT target: " + auth_err;
            return req;
        }
        if (!connect_port.has_value()) {
            req.status = ParseStatus::Error;
            req.error_message = "CONNECT requires an explicit port in request target";
            return req;
        }
        if (connect_host.empty()) {
            req.status = ParseStatus::Error;
            req.error_message = "CONNECT target missing host";
            return req;
        }

        req.host = connect_host;
        req.port = *connect_port;
        req.path = "";
        req.status = ParseStatus::Success;
        req.valid = true;
        return req;
    }

    // Standard HTTP request methods (GET, POST, etc.)
    std::string target_host;
    std::optional<uint16_t> target_port;
    uint16_t default_scheme_port = 80;

    std::string_view target_view = req.request_target;
    if (target_view.size() >= 7 && iequals(target_view.substr(0, 7), "http://")) {
        default_scheme_port = 80;
        std::string_view after_scheme = target_view.substr(7);
        size_t slash_pos = after_scheme.find('/');
        std::string_view authority;
        if (slash_pos == std::string_view::npos) {
            authority = after_scheme;
            req.path = "/";
        } else {
            authority = after_scheme.substr(0, slash_pos);
            req.path = std::string(after_scheme.substr(slash_pos));
        }

        std::string auth_error;
        if (!parse_authority(authority, target_host, target_port, auth_error)) {
            req.status = ParseStatus::Error;
            req.error_message = "Invalid authority in request target: " + auth_error;
            return req;
        }
    } else if (target_view.size() >= 8 && iequals(target_view.substr(0, 8), "https://")) {
        default_scheme_port = 443;
        std::string_view after_scheme = target_view.substr(8);
        size_t slash_pos = after_scheme.find('/');
        std::string_view authority;
        if (slash_pos == std::string_view::npos) {
            authority = after_scheme;
            req.path = "/";
        } else {
            authority = after_scheme.substr(0, slash_pos);
            req.path = std::string(after_scheme.substr(slash_pos));
        }

        std::string auth_error;
        if (!parse_authority(authority, target_host, target_port, auth_error)) {
            req.status = ParseStatus::Error;
            req.error_message = "Invalid authority in request target: " + auth_error;
            return req;
        }
    } else {
        req.path = req.request_target;
    }

    // Parse Host header if present
    std::string header_host;
    std::optional<uint16_t> header_port;
    if (!req.host_header.empty()) {
        std::string host_error;
        if (!parse_authority(req.host_header, header_host, header_port, host_error)) {
            req.status = ParseStatus::Error;
            req.error_message = "Invalid Host header: " + host_error;
            return req;
        }
    }

    // Determine final host and port:
    // When an absolute URI is present, it determines the destination completely.
    // The Host header must not override the destination or port.
    if (!target_host.empty()) {
        req.host = target_host;
        if (target_port.has_value()) {
            req.port = *target_port;
        } else {
            req.port = default_scheme_port;
        }
    } else if (!header_host.empty()) {
        req.host = header_host;
        if (header_port.has_value()) {
            req.port = *header_port;
        } else {
            req.port = default_scheme_port;
        }
    } else {
        req.status = ParseStatus::Error;
        req.error_message = "Missing Host header and no absolute URI authority provided";
        return req;
    }

    if (req.path.empty()) {
        req.path = "/";
    } else if (req.path.front() != '/' && req.path != "*") {
        req.status = ParseStatus::Error;
        req.error_message = "Request path must start with '/'";
        return req;
    }

    req.status = ParseStatus::Success;
    req.valid = true;
    return req;
}

std::string HttpParser::make_400_response() {
    const std::string body = "Bad Request\n";
    return "HTTP/1.1 400 Bad Request\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

std::string HttpParser::sanitize_path(std::string_view path) {
    size_t q_pos = path.find('?');
    if (q_pos != std::string_view::npos) {
        return std::string(path.substr(0, q_pos));
    }
    return std::string(path);
}
