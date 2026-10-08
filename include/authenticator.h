#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <string>
#include <string_view>

class Authenticator {
public:
    static constexpr const char* DEFAULT_USERNAME = "palak";
    static constexpr const char* DEFAULT_PASSWORD = "secureproxy";
    static constexpr const char* REALM = "SecureProxyGateway";

    explicit Authenticator(std::string username = DEFAULT_USERNAME,
                           std::string password = DEFAULT_PASSWORD);

    bool authenticate(std::string_view auth_header) const;

    static std::string make_407_response();

    const std::string& username() const { return username_; }

    static bool base64_decode(std::string_view in, std::string& out);
    static std::string base64_encode(std::string_view in);

private:
    std::string username_;
    std::string password_;
};

#endif // AUTHENTICATOR_H
