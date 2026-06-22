#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <openssl/err.h>

extern "C" bool generate_ecdsa_keypair(const char* curve_name, const char* private_key_path, const char* public_key_path) noexcept;
extern "C" bool generate_rsa_keypair(int bits, const char* private_key_path, const char* public_key_path) noexcept;
extern "C" bool sign_ecdsa(const char* private_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool sign_rsapss(const char* private_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool verify_ecdsa(const char* public_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool verify_rsapss(const char* public_key_path, const char* message_path, const char* signature_path) noexcept;

using namespace std;

static void WriteFile(const string& path, const vector<uint8_t>& data) {
    ofstream f(path, ios::binary);
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static vector<uint8_t> ReadFile(const string& path) {
    ifstream f(path, ios::binary | ios::ate);
    streamsize size = f.tellg();
    f.seekg(0, ios::beg);
    vector<uint8_t> buffer(size);
    if (f.read(reinterpret_cast<char*>(buffer.data()), size)) return buffer;
    return {};
}

TEST_CASE("ECDSA Negative Tests", "[ecdsa]") {
    string priv = "test_ecdsa_priv.pem";
    string pub = "test_ecdsa_pub.pem";
    string msg = "test_ecdsa_msg.bin";
    string sig = "test_ecdsa_sig.bin";

    vector<uint8_t> message = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    WriteFile(msg, message);

    REQUIRE(generate_ecdsa_keypair("prime256v1", priv.c_str(), pub.c_str()) == true);
    REQUIRE(sign_ecdsa(priv.c_str(), msg.c_str(), sig.c_str()) == true);

    SECTION("Valid Signature") {
        REQUIRE(verify_ecdsa(pub.c_str(), msg.c_str(), sig.c_str()) == true);
    }

    SECTION("Modified Message -> Fails") {
        vector<uint8_t> tampered_msg = message;
        tampered_msg[0] ^= 0x01;
        WriteFile(msg, tampered_msg);
        REQUIRE(verify_ecdsa(pub.c_str(), msg.c_str(), sig.c_str()) == false);
    }

    SECTION("Modified Signature -> Fails") {
        vector<uint8_t> signature = ReadFile(sig);
        if (!signature.empty()) {
            signature[signature.size() / 2] ^= 0xFF;
            WriteFile(sig, signature);
            REQUIRE(verify_ecdsa(pub.c_str(), msg.c_str(), sig.c_str()) == false);
        }
    }

    SECTION("Modified Public Key -> Fails") {
        vector<uint8_t> public_key = ReadFile(pub);
        if (public_key.size() > 50) {
            public_key[40] ^= 0x01;
            WriteFile(pub, public_key);
            REQUIRE(verify_ecdsa(pub.c_str(), msg.c_str(), sig.c_str()) == false);
        }
    }

    SECTION("Wrong Algorithm Identifier -> Fails") {
        // Try verifying an ECDSA signature using RSA-PSS
        REQUIRE(verify_rsapss(pub.c_str(), msg.c_str(), sig.c_str()) == false);
    }

    filesystem::remove(priv);
    filesystem::remove(pub);
    filesystem::remove(msg);
    filesystem::remove(sig);
}

TEST_CASE("RSA-PSS Negative Tests", "[rsapss]") {
    string priv = "test_rsa_priv.pem";
    string pub = "test_rsa_pub.pem";
    string msg = "test_rsa_msg.bin";
    string sig = "test_rsa_sig.bin";

    vector<uint8_t> message = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    WriteFile(msg, message);

    REQUIRE(generate_rsa_keypair(2048, priv.c_str(), pub.c_str()) == true);
    REQUIRE(sign_rsapss(priv.c_str(), msg.c_str(), sig.c_str()) == true);

    SECTION("Valid Signature") {
        REQUIRE(verify_rsapss(pub.c_str(), msg.c_str(), sig.c_str()) == true);
    }

    SECTION("Modified Message -> Fails") {
        vector<uint8_t> tampered_msg = message;
        tampered_msg[0] ^= 0x01;
        WriteFile(msg, tampered_msg);
        REQUIRE(verify_rsapss(pub.c_str(), msg.c_str(), sig.c_str()) == false);
    }

    SECTION("Modified Signature -> Fails") {
        vector<uint8_t> signature = ReadFile(sig);
        if (!signature.empty()) {
            signature[signature.size() / 2] ^= 0xFF;
            WriteFile(sig, signature);
            REQUIRE(verify_rsapss(pub.c_str(), msg.c_str(), sig.c_str()) == false);
        }
    }

    SECTION("Modified Public Key -> Fails") {
        vector<uint8_t> public_key = ReadFile(pub);
        if (public_key.size() > 50) {
            public_key[40] ^= 0x01;
            WriteFile(pub, public_key);
            REQUIRE(verify_rsapss(pub.c_str(), msg.c_str(), sig.c_str()) == false);
        }
    }

    SECTION("Wrong Algorithm Identifier -> Fails") {
        // Try verifying an RSA-PSS signature using ECDSA
        REQUIRE(verify_ecdsa(pub.c_str(), msg.c_str(), sig.c_str()) == false);
    }

    filesystem::remove(priv);
    filesystem::remove(pub);
    filesystem::remove(msg);
    filesystem::remove(sig);
}
