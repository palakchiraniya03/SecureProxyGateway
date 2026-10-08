#include "authenticator.h"

#include <iostream>
#include <string>

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
    std::cout << "Running Authenticator Test Suite..." << std::endl;

    Authenticator auth;

    // Test 1: Valid credentials (palak:secureproxy -> cGFsYWs6c2VjdXJlcHJveHk=)
    {
        std::string valid_header = "Basic cGFsYWs6c2VjdXJlcHJveHk=";
        assert_test(auth.authenticate(valid_header), "Valid credentials authenticate successfully");
    }

    // Test 2: Case-insensitive "basic " scheme prefix
    {
        std::string lower_header = "basic cGFsYWs6c2VjdXJlcHJveHk=";
        assert_test(auth.authenticate(lower_header), "Case-insensitive basic prefix authenticates successfully");
    }

    // Test 3: Invalid password (palak:wrongpass -> cGFsYWs6d3JvbmdwYXNz)
    {
        std::string bad_pass = "Basic cGFsYWs6d3JvbmdwYXNz";
        assert_test(!auth.authenticate(bad_pass), "Invalid password is rejected");
    }

    // Test 4: Invalid username (wronguser:secureproxy -> d3Jvbmd1c2VyOnNlY3VyZXByb3h5)
    {
        std::string bad_user = "Basic d3Jvbmd1c2VyOnNlY3VyZXByb3h5";
        assert_test(!auth.authenticate(bad_user), "Invalid username is rejected");
    }

    // Test 5: Missing Proxy-Authorization header
    {
        assert_test(!auth.authenticate(""), "Empty/missing Proxy-Authorization is rejected");
    }

    // Test 6: Unsupported authentication scheme (e.g. Bearer)
    {
        std::string bearer = "Bearer cGFsYWs6c2VjdXJlcHJveHk=";
        assert_test(!auth.authenticate(bearer), "Unsupported Bearer scheme is rejected");
    }

    // Test 7: Missing "Basic " prefix
    {
        std::string raw_b64 = "cGFsYWs6c2VjdXJlcHJveHk=";
        assert_test(!auth.authenticate(raw_b64), "Missing scheme prefix is rejected");
    }

    // Test 8: Malformed Base64 data (invalid characters)
    {
        std::string corrupt = "Basic ???invalid-base64???";
        assert_test(!auth.authenticate(corrupt), "Malformed base64 characters rejected");
    }

    // Test 9: Malformed Base64 length / padding
    {
        std::string bad_len = "Basic abc";
        assert_test(!auth.authenticate(bad_len), "Malformed base64 length rejected");
    }

    // Test 10: Missing colon in decoded credentials (palak -> cGFsYWs=)
    {
        std::string no_colon = "Basic cGFsYWs=";
        assert_test(!auth.authenticate(no_colon), "Credentials without colon separator rejected");
    }

    // Test 11: Empty Base64 payload after scheme
    {
        std::string empty_payload = "Basic ";
        assert_test(!auth.authenticate(empty_payload), "Empty Basic payload rejected");
    }

    // Test 12: 407 response structure verification
    {
        std::string resp = Authenticator::make_407_response();
        assert_test(resp.find("HTTP/1.1 407 Proxy Authentication Required") != std::string::npos,
                    "407 response contains HTTP status line");
        assert_test(resp.find("Proxy-Authenticate: Basic realm=\"SecureProxyGateway\"") != std::string::npos,
                    "407 response contains Proxy-Authenticate header with realm");
        assert_test(resp.find("Connection: close") != std::string::npos,
                    "407 response contains Connection: close");
    }

    // Test 13: 407 Content-Length exactly matches body size
    {
        std::string resp = Authenticator::make_407_response();
        size_t header_sep = resp.find("\r\n\r\n");
        assert_test(header_sep != std::string::npos, "407 response contains header separator");

        std::string body = resp.substr(header_sep + 4);
        std::string cl_needle = "Content-Length: ";
        size_t cl_pos = resp.find(cl_needle);
        assert_test(cl_pos != std::string::npos, "407 response contains Content-Length header");

        size_t cl_end = resp.find("\r\n", cl_pos);
        std::string cl_str = resp.substr(cl_pos + cl_needle.size(), cl_end - (cl_pos + cl_needle.size()));
        size_t cl_val = std::stoul(cl_str);

        assert_test(cl_val == body.size(),
                    "407 Content-Length exactly matches response body size",
                    "Expected: " + std::to_string(body.size()) + ", Got: " + std::to_string(cl_val));
    }

    // Test 14: Focused test - password containing a colon (user:pa:ss)
    {
        Authenticator auth_colon("user", "pa:ss");
        std::string encoded = "Basic " + Authenticator::base64_encode("user:pa:ss");
        assert_test(auth_colon.authenticate(encoded),
                    "Password containing colon (user:pa:ss) authenticates successfully");

        std::string wrong_pass = "Basic " + Authenticator::base64_encode("user:pa");
        assert_test(!auth_colon.authenticate(wrong_pass),
                    "Partial password before colon is rejected");
    }

    // Test 15: Focused test - empty password (user:)
    {
        Authenticator auth_empty_pass("user", "");
        std::string encoded = "Basic " + Authenticator::base64_encode("user:");
        assert_test(auth_empty_pass.authenticate(encoded),
                    "Empty password (user:) authenticates successfully");

        std::string non_empty = "Basic " + Authenticator::base64_encode("user:notempty");
        assert_test(!auth_empty_pass.authenticate(non_empty),
                    "Non-empty password rejected when empty expected");
    }

    // Test 16: Focused test - empty username (:password)
    {
        Authenticator auth_empty_user("", "password");
        std::string encoded = "Basic " + Authenticator::base64_encode(":password");
        assert_test(auth_empty_user.authenticate(encoded),
                    "Empty username (:password) authenticates successfully");

        std::string non_empty = "Basic " + Authenticator::base64_encode("user:password");
        assert_test(!auth_empty_user.authenticate(non_empty),
                    "Non-empty username rejected when empty expected");
    }

    // Test 17: Focused test - long Proxy-Authorization header value
    {
        std::string long_garbage(4096, 'A');
        std::string long_header = "Basic " + long_garbage;
        assert_test(!auth.authenticate(long_header),
                    "Long Proxy-Authorization header handled safely and rejected");
    }

    // Test 18: Custom credentials constructor
    {
        Authenticator custom_auth("alice", "wonderland");
        std::string encoded = "Basic " + Authenticator::base64_encode("alice:wonderland");
        assert_test(custom_auth.authenticate(encoded),
                    "Custom credentials authenticate successfully");
        assert_test(!custom_auth.authenticate("Basic cGFsYWs6c2VjdXJlcHJveHk="),
                    "Default credentials rejected by custom Authenticator");
    }

    // Test 19: 407 response does not expose credentials
    {
        std::string resp = Authenticator::make_407_response();
        assert_test(resp.find("palak") == std::string::npos &&
                    resp.find("secureproxy") == std::string::npos,
                    "407 response does not expose credentials");
    }

    std::cout << "\nTest Results: " << g_passed << " passed, " << g_failed << " failed." << std::endl;
    return g_failed == 0 ? 0 : 1;
}
