#include "http_parser.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

void assert_test(bool condition, const std::string& test_name, const std::string& details = "") {
    if (condition) {
        std::cout << "[PASS] " << test_name << std::endl;
        g_passed++;
    } else {
        std::cerr << "[FAIL] " << test_name;
        if (!details.empty()) {
            std::cerr << " (" << details << ")";
        }
        std::cerr << std::endl;
        g_failed++;
    }
}

} // namespace

int main() {
    std::cout << "Running HTTP Parser Test Suite..." << std::endl;

    // Test 1: Standard forward proxy request (Absolute URI)
    {
        std::string raw =
            "GET http://example.com/index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Valid absolute URI request is parsed as valid");
        assert_test(req.method == "GET", "Method is GET", "Got: " + req.method);
        assert_test(req.request_target == "http://example.com/index.html", "Request target matches", "Got: " + req.request_target);
        assert_test(req.version == "HTTP/1.1", "Version is HTTP/1.1", "Got: " + req.version);
        assert_test(req.host == "example.com", "Host is example.com", "Got: " + req.host);
        assert_test(req.port == 80, "Port is 80", "Got: " + std::to_string(req.port));
        assert_test(req.path == "/index.html", "Path is /index.html", "Got: " + req.path);
    }

    // Test 2: Absolute URI with explicit port in Host header
    {
        std::string raw =
            "GET http://example.com/index.html HTTP/1.1\r\n"
            "Host: example.com:8080\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Valid request with explicit port in Host header is valid");
        assert_test(req.host == "example.com", "Host is example.com", "Got: " + req.host);
        assert_test(req.port == 8080, "Port is 8080", "Got: " + std::to_string(req.port));
        assert_test(req.path == "/index.html", "Path is /index.html", "Got: " + req.path);
    }

    // Test 3: Origin-form request with explicit port in Host header
    {
        std::string raw =
            "POST /api/v1/resource HTTP/1.1\r\n"
            "Host: example.com:8080\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Origin-form with Host: example.com:8080 is valid");
        assert_test(req.method == "POST", "Method is POST", "Got: " + req.method);
        assert_test(req.request_target == "/api/v1/resource", "Target is /api/v1/resource", "Got: " + req.request_target);
        assert_test(req.host == "example.com", "Host is example.com", "Got: " + req.host);
        assert_test(req.port == 8080, "Port is 8080", "Got: " + std::to_string(req.port));
        assert_test(req.path == "/api/v1/resource", "Path is /api/v1/resource", "Got: " + req.path);
    }

    // Test 4: Target with explicit port and query params
    {
        std::string raw =
            "GET http://example.com:9000/search?q=test&lang=en HTTP/1.1\r\n"
            "Host: example.com:9000\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Target with explicit port and query is valid");
        assert_test(req.port == 9000, "Port is 9000", "Got: " + std::to_string(req.port));
        assert_test(req.path == "/search?q=test&lang=en", "Path includes query", "Got: " + req.path);
    }

    // Test 5: Target absolute URI without path defaults to "/"
    {
        std::string raw =
            "GET http://example.com HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Target without path is valid");
        assert_test(req.path == "/", "Path defaults to /", "Got: " + req.path);
    }

    // Test 6: Case-insensitive header name and ignoring extra headers
    {
        std::string raw =
            "GET /index.html HTTP/1.1\r\n"
            "hOsT: example.com\r\n"
            "uSeR-AgEnT: curl/7.88.1\r\n"
            "AcCePt: */*\r\n"
            "X-Custom-Header: IgnoreMe\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Case-insensitive headers and unneeded headers ignored");
        assert_test(req.host == "example.com", "Host parsed case-insensitively", "Got: " + req.host);
        assert_test(req.port == 80, "Port is 80", "Got: " + std::to_string(req.port));
    }

    // Test 7: Malformed request - too many tokens in request line
    {
        std::string raw = "GET / HTTP/1.1 EXTRA\r\nHost: example.com\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject request line with too many tokens");
    }

    // Test 8: Malformed request - too few tokens in request line
    {
        std::string raw = "GET /\r\nHost: example.com\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject request line with too few tokens");
    }

    // Test 9: Malformed request - invalid HTTP version
    {
        std::string raw = "GET / INVALID/1.1\r\nHost: example.com\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject invalid HTTP version");
    }

    // Test 10: Malformed request - missing Host header in HTTP/1.1 origin-form
    {
        std::string raw = "GET /index.html HTTP/1.1\r\nUser-Agent: curl\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject HTTP/1.1 request missing Host header");
    }

    // Test 11: Malformed request - out of range port
    {
        std::string raw = "GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject out-of-range port number");
    }

    // Test 12: Malformed request - non-numeric port
    {
        std::string raw = "GET / HTTP/1.1\r\nHost: example.com:abc\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject non-numeric port number");
    }

    // Test 13: Malformed request - invalid header syntax (no colon)
    {
        std::string raw = "GET / HTTP/1.1\r\nHostMissingColon\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject header line missing colon");
    }

    // Test 14: Malformed request - whitespace before colon in header name
    {
        std::string raw = "GET / HTTP/1.1\r\nHost : example.com\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject header with whitespace before colon");
    }

    // Test 15: Malformed request - empty host in absolute URI
    {
        std::string raw = "GET http:///path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject empty host in absolute URI");
    }

    // --- NEW REVIEW FIX TESTS ---

    // Test 16: CONNECT method - valid authority-form
    {
        std::string raw =
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Valid CONNECT request is valid");
        assert_test(req.method == "CONNECT", "CONNECT method matches", "Got: " + req.method);
        assert_test(req.host == "example.com", "CONNECT host matches", "Got: " + req.host);
        assert_test(req.port == 443, "CONNECT port is 443", "Got: " + std::to_string(req.port));
        assert_test(req.path.empty(), "CONNECT has no normal path", "Got: '" + req.path + "'");
    }

    // Test 17: CONNECT method - missing port
    {
        std::string raw =
            "CONNECT example.com HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject CONNECT request with missing port");
    }

    // Test 18: CONNECT method - invalid/non-numeric port
    {
        std::string raw =
            "CONNECT example.com:abc HTTP/1.1\r\n"
            "Host: example.com:abc\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject CONNECT request with invalid port");
    }

    // Test 19: CONNECT method - IPv6 authority
    {
        std::string raw =
            "CONNECT [::1]:443 HTTP/1.1\r\n"
            "Host: [::1]:443\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Valid IPv6 CONNECT request is valid");
        assert_test(req.method == "CONNECT", "IPv6 CONNECT method is CONNECT");
        assert_test(req.host == "::1", "IPv6 CONNECT host is ::1", "Got: " + req.host);
        assert_test(req.port == 443, "IPv6 CONNECT port is 443", "Got: " + std::to_string(req.port));
        assert_test(req.path.empty(), "IPv6 CONNECT has empty path");
    }

    // Test 20: Correct default port for https:// scheme (443)
    {
        std::string raw =
            "GET https://secure.example.com/login HTTP/1.1\r\n"
            "Host: secure.example.com\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "HTTPS absolute URI is valid");
        assert_test(req.port == 443, "Default port for https:// is 443", "Got: " + std::to_string(req.port));
        assert_test(req.path == "/login", "Path for HTTPS is /login", "Got: " + req.path);
    }

    // Test 21: Correct default port for http:// scheme (80)
    {
        std::string raw =
            "GET http://insecure.example.com/test HTTP/1.1\r\n"
            "Host: insecure.example.com\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "HTTP absolute URI is valid");
        assert_test(req.port == 80, "Default port for http:// is 80", "Got: " + std::to_string(req.port));
    }

    // Test 22: Incomplete request - header terminator not yet received
    {
        std::string raw = "GET /index.html HTTP/1.1\r\nHost: example.com";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid, "Incomplete request has valid == false");
        assert_test(req.is_incomplete(), "Incomplete request status is Incomplete");
        assert_test(!req.is_error(), "Incomplete request is not an Error");
    }

    // Test 23: Incomplete request - empty string
    {
        HttpRequest req = HttpParser::parse("");
        assert_test(!req.valid, "Empty input has valid == false");
        assert_test(req.is_incomplete(), "Empty input status is Incomplete");
    }

    // Test 24: Expose position where headers end (header_length)
    {
        std::string raw =
            "GET /index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n"
            "body-payload-here";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Request with trailing body parsed as valid");
        assert_test(req.header_length > 0, "header_length is non-zero");
        std::string body(raw.substr(req.header_length));
        assert_test(body == "body-payload-here", "Bytes after header_length match body payload", "Got: " + body);
    }

    // Test 25: 8 KB maximum header block size - rejected when oversized without terminator
    {
        std::string oversized(8193, 'A');
        HttpRequest req = HttpParser::parse(oversized);
        assert_test(!req.valid, "Oversized request is invalid");
        assert_test(req.is_error(), "Oversized request status is Error");
        assert_test(!req.is_incomplete(), "Oversized request is not treated as incomplete");
    }

    // Test 26: 8 KB maximum header block size - rejected when header block > 8 KB with terminator
    {
        std::string large_header(8200, 'X');
        std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: " + large_header + "\r\n\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Header block exceeding 8 KB with terminator is rejected as Error");
    }

    // Test 27: Preserve Proxy-Authorization header
    {
        std::string raw =
            "CONNECT internal.corp:443 HTTP/1.1\r\n"
            "Host: internal.corp:443\r\n"
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "CONNECT with Proxy-Authorization is valid");
        assert_test(req.proxy_authorization == "Basic dXNlcjpwYXNzd29yZA==",
                    "Proxy-Authorization header preserved", "Got: " + req.proxy_authorization);
    }

    // Test 28: Preserve and parse valid Content-Length header
    {
        std::string raw =
            "POST /api/upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 1048576\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "POST with Content-Length is valid");
        assert_test(req.content_length.has_value() && *req.content_length == 1048576,
                    "Content-Length parsed correctly",
                    "Got: " + (req.content_length ? std::to_string(*req.content_length) : "none"));
    }

    // Test 29: Reject negative Content-Length
    {
        std::string raw =
            "POST /api/upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: -50\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject negative Content-Length");
    }

    // Test 30: Reject non-numeric Content-Length
    {
        std::string raw =
            "POST /api/upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 123abc45\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(!req.valid && req.is_error(), "Reject non-numeric Content-Length");
    }

    // Test 31: Normalize hostname to lowercase
    {
        std::string raw =
            "GET http://EXAMPLE.COM/index.html HTTP/1.1\r\n"
            "Host: EXAMPLE.COM\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Uppercase absolute URI is valid");
        assert_test(req.host == "example.com", "Host normalized to lowercase from target", "Got: " + req.host);
    }

    // Test 32: Normalize hostname to lowercase from Host header
    {
        std::string raw =
            "GET /index.html HTTP/1.1\r\n"
            "Host: MySubdomain.EXAMPLE.Org:8080\r\n"
            "\r\n";
        HttpRequest req = HttpParser::parse(raw);
        assert_test(req.valid, "Mixed case Host header is valid");
        assert_test(req.host == "mysubdomain.example.org", "Host normalized to lowercase from header", "Got: " + req.host);
        assert_test(req.port == 8080, "Port preserved as 8080");
    }

    // Test 33: 400 Bad Request response structure and exact Content-Length match
    {
        std::string resp = HttpParser::make_400_response();
        assert_test(resp.find("HTTP/1.1 400 Bad Request") != std::string::npos,
                    "400 response contains status line");
        assert_test(resp.find("Connection: close") != std::string::npos,
                    "400 response contains Connection: close");

        size_t header_sep = resp.find("\r\n\r\n");
        assert_test(header_sep != std::string::npos, "400 response contains header separator");

        std::string body = resp.substr(header_sep + 4);
        std::string cl_needle = "Content-Length: ";
        size_t cl_pos = resp.find(cl_needle);
        assert_test(cl_pos != std::string::npos, "400 response contains Content-Length header");

        size_t cl_end = resp.find("\r\n", cl_pos);
        std::string cl_str = resp.substr(cl_pos + cl_needle.size(), cl_end - (cl_pos + cl_needle.size()));
        size_t cl_val = std::stoul(cl_str);

        assert_test(cl_val == body.size(),
                    "400 Content-Length exactly matches body size",
                    "Expected: " + std::to_string(body.size()) + ", Got: " + std::to_string(cl_val));
    }

    // Test 34: Path sanitization strips query parameters
    {
        assert_test(HttpParser::sanitize_path("/page?token=secret123") == "/page",
                    "sanitize_path strips query token from /page?token=secret123");
        assert_test(HttpParser::sanitize_path("/api/search?q=test&page=2") == "/api/search",
                    "sanitize_path strips complex query from /api/search");
        assert_test(HttpParser::sanitize_path("/index.html") == "/index.html",
                    "sanitize_path preserves path without query");
        assert_test(HttpParser::sanitize_path("") == "",
                    "sanitize_path handles empty path");
    }

    std::cout << "\nTest Results: " << g_passed << " passed, " << g_failed << " failed." << std::endl;
    return g_failed == 0 ? 0 : 1;
}
