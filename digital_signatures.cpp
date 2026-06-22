#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static constexpr const char* LAB_NAME = "Lab 5 Digital Signatures OpenSSL Core";

#if defined(_WIN32)
#define SIGN_API extern "C" __declspec(dllexport)
#else
#define SIGN_API extern "C" __attribute__((visibility("default")))
#endif

template <typename T, void (*FreeFn)(T*)>
using ossl_ptr = std::unique_ptr<T, decltype(FreeFn)>;

using EVP_PKEY_ptr = ossl_ptr<EVP_PKEY, EVP_PKEY_free>;
using EVP_PKEY_CTX_ptr = ossl_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using EVP_MD_CTX_ptr = ossl_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;
using BIO_ptr = ossl_ptr<BIO, BIO_free_all>;

namespace {
thread_local std::string g_last_error;

void clear_error() noexcept {
    try {
        g_last_error.clear();
    } catch (...) {
    }
}

void set_error(const std::string& message) noexcept {
    try {
        g_last_error = message;
    } catch (...) {
    }
}

void set_openssl_error(const std::string& context) noexcept {
    try {
        unsigned long code = ERR_get_error();
        if (code == 0) {
            g_last_error = context;
            return;
        }
        char buffer[256] = {};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        g_last_error = context + ": " + buffer;
    } catch (...) {
    }
}

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("cannot open file for reading: " + path);
    }
    const std::streamsize size = file.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine file size: " + path);
    }
    std::vector<unsigned char> data(static_cast<std::size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!data.empty() && !file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw std::runtime_error("cannot read file: " + path);
    }
    return data;
}

bool write_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    if (!data.empty()) {
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    return file.good();
}

bool write_private_key(EVP_PKEY* key, const std::string& path) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "wb"), BIO_free_all);
    return bio && PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
}

bool write_public_key(EVP_PKEY* key, const std::string& path) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "wb"), BIO_free_all);
    return bio && PEM_write_bio_PUBKEY(bio.get(), key) == 1;
}

EVP_PKEY_ptr load_private_key(const std::string& path) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "rb"), BIO_free_all);
    if (!bio) return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    return EVP_PKEY_ptr(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
}

EVP_PKEY_ptr load_public_key(const std::string& path) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "rb"), BIO_free_all);
    if (!bio) return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    return EVP_PKEY_ptr(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
}

int curve_nid_from_name(const std::string& curve) {
    if (curve == "prime256v1" || curve == "secp256r1" || curve == "P-256" || curve == "p-256") {
        return NID_X9_62_prime256v1;
    }
    if (curve == "secp384r1" || curve == "P-384" || curve == "p-384") {
        return NID_secp384r1;
    }
    return OBJ_txt2nid(curve.c_str());
}

bool generate_ecdsa_impl(const std::string& curve_name, const std::string& private_key_path, const std::string& public_key_path) {
    const int nid = curve_nid_from_name(curve_name);
    if (nid == NID_undef) {
        set_error("unsupported EC curve: " + curve_name);
        return false;
    }

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid) <= 0) {
        set_openssl_error("EC keygen initialization failed");
        return false;
    }

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        set_openssl_error("EC keygen failed");
        return false;
    }
    EVP_PKEY_ptr key(raw, EVP_PKEY_free);
    if (!write_private_key(key.get(), private_key_path) || !write_public_key(key.get(), public_key_path)) {
        set_openssl_error("writing EC keypair failed");
        return false;
    }
    return true;
}

bool generate_rsa_impl(int bits, const std::string& private_key_path, const std::string& public_key_path) {
    if (bits < 2048) {
        set_error("RSA key size must be at least 2048 bits");
        return false;
    }

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        set_openssl_error("RSA keygen initialization failed");
        return false;
    }

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        set_openssl_error("RSA keygen failed");
        return false;
    }
    EVP_PKEY_ptr key(raw, EVP_PKEY_free);
    if (!write_private_key(key.get(), private_key_path) || !write_public_key(key.get(), public_key_path)) {
        set_openssl_error("writing RSA keypair failed");
        return false;
    }
    return true;
}

bool sign_impl(const std::string& mode, const std::string& private_key_path, const std::string& message_path, const std::string& signature_path) {
    EVP_PKEY_ptr key = load_private_key(private_key_path);
    if (!key) {
        set_openssl_error("loading private key failed");
        return false;
    }
    const std::vector<unsigned char> message = read_file(message_path);

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    const EVP_MD* hash_algo = (mode == "ecdsa-p384") ? EVP_sha384() : EVP_sha256();
    if (!ctx || EVP_DigestSignInit(ctx.get(), &pkey_ctx, hash_algo, nullptr, key.get()) <= 0) {
        set_openssl_error("DigestSignInit failed");
        return false;
    }
    if (mode == "rsapss") {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0) {
            set_openssl_error("configuring RSA-PSS failed");
            return false;
        }
    }

    std::size_t sig_len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, message.data(), message.size()) <= 0) {
        set_openssl_error("DigestSign size query failed");
        return false;
    }
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, message.data(), message.size()) <= 0) {
        set_openssl_error("DigestSign failed");
        return false;
    }
    signature.resize(sig_len);
    if (!write_file(signature_path, signature)) {
        set_error("writing signature failed: " + signature_path);
        return false;
    }
    return true;
}

bool verify_impl(const std::string& mode, const std::string& public_key_path, const std::string& message_path, const std::string& signature_path) {
    EVP_PKEY_ptr key = load_public_key(public_key_path);
    if (!key) {
        set_openssl_error("loading public key failed");
        return false;
    }
    const std::vector<unsigned char> message = read_file(message_path);
    const std::vector<unsigned char> signature = read_file(signature_path);

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    const EVP_MD* hash_algo = (mode == "ecdsa-p384") ? EVP_sha384() : EVP_sha256();
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), &pkey_ctx, hash_algo, nullptr, key.get()) <= 0) {
        set_openssl_error("DigestVerifyInit failed");
        return false;
    }
    if (mode == "rsapss") {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0) {
            set_openssl_error("configuring RSA-PSS failed");
            return false;
        }
    }

    const int ok = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size());
    if (ok != 1) {
        if (ok < 0) set_openssl_error("DigestVerify failed");
        else set_error("signature is invalid");
        return false;
    }
    return true;
}

std::uint64_t checksum_file_prefix(const unsigned char* input, std::size_t input_len) {
    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    SHA256(input, input_len, digest);
    std::uint64_t out = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        out = (out << 8) | static_cast<std::uint64_t>(digest[i]);
    }
    return out;
}
}

SIGN_API const char* get_last_error() noexcept {
    return g_last_error.c_str();
}

SIGN_API void free_memory(void* p) noexcept {
    std::free(p);
}

SIGN_API bool generate_ecdsa_keypair(const char* curve_name, const char* private_key_path, const char* public_key_path) noexcept {
    clear_error();
    if (curve_name == nullptr || private_key_path == nullptr || public_key_path == nullptr) {
        set_error("generate_ecdsa_keypair requires curve_name, private_key_path, and public_key_path");
        return false;
    }
    try {
        return generate_ecdsa_impl(curve_name, private_key_path, public_key_path);
    } catch (const std::exception& exc) {
        set_error(exc.what());
        return false;
    }
}

SIGN_API bool generate_rsa_keypair(int bits, const char* private_key_path, const char* public_key_path) noexcept {
    clear_error();
    if (private_key_path == nullptr || public_key_path == nullptr) {
        set_error("generate_rsa_keypair requires private_key_path and public_key_path");
        return false;
    }
    try {
        return generate_rsa_impl(bits, private_key_path, public_key_path);
    } catch (const std::exception& exc) {
        set_error(exc.what());
        return false;
    }
}

SIGN_API bool sign_ecdsa(const char* private_key_path, const char* message_path, const char* signature_path) noexcept {
    clear_error();
    if (private_key_path == nullptr || message_path == nullptr || signature_path == nullptr) {
        set_error("sign_ecdsa requires private_key_path, message_path, and signature_path");
        return false;
    }
    try {
        return sign_impl("ecdsa", private_key_path, message_path, signature_path);
    } catch (const std::exception& exc) {
        set_error(exc.what());
        return false;
    }
}

SIGN_API bool sign_ecdsa_p384(const char* private_key_path, const char* message_path, const char* signature_path) noexcept {
    clear_error();
    if (private_key_path == nullptr || message_path == nullptr || signature_path == nullptr) return false;
    try {
        return sign_impl("ecdsa-p384", private_key_path, message_path, signature_path);
    } catch (...) { return false; }
}

SIGN_API bool verify_ecdsa_p384(const char* public_key_path, const char* message_path, const char* signature_path) noexcept {
    clear_error();
    if (public_key_path == nullptr || message_path == nullptr || signature_path == nullptr) return false;
    try {
        return verify_impl("ecdsa-p384", public_key_path, message_path, signature_path);
    } catch (...) { return false; }
}

SIGN_API bool sign_rsapss(const char* private_key_path, const char* message_path, const char* signature_path) noexcept {
    clear_error();
    if (private_key_path == nullptr || message_path == nullptr || signature_path == nullptr) {
        set_error("sign_rsapss requires private_key_path, message_path, and signature_path");
        return false;
    }
    try {
        return sign_impl("rsapss", private_key_path, message_path, signature_path);
    } catch (const std::exception& exc) {
        set_error(exc.what());
        return false;
    }
}

SIGN_API bool verify_ecdsa(const char* public_key_path, const char* message_path, const char* signature_path) noexcept {
    clear_error();
    if (public_key_path == nullptr || message_path == nullptr || signature_path == nullptr) {
        set_error("verify_ecdsa requires public_key_path, message_path, and signature_path");
        return false;
    }
    try {
        return verify_impl("ecdsa", public_key_path, message_path, signature_path);
    } catch (const std::exception& exc) {
        set_error(exc.what());
        return false;
    }
}

SIGN_API bool verify_rsapss(const char* public_key_path, const char* message_path, const char* signature_path) noexcept {
    clear_error();
    if (public_key_path == nullptr || message_path == nullptr || signature_path == nullptr) {
        set_error("verify_rsapss requires public_key_path, message_path, and signature_path");
        return false;
    }
    try {
        return verify_impl("rsapss", public_key_path, message_path, signature_path);
    } catch (const std::exception& exc) {
        set_error(exc.what());
        return false;
    }
}

SIGN_API const char* lab_crypto_name() {
    return LAB_NAME;
}

SIGN_API const char* lab_crypto_version() {
    return "24521631-lab5-openssl-signatures-3.0";
}

SIGN_API std::uint64_t lab_native_checksum(const unsigned char* input, std::size_t input_len) {
    if (input == nullptr && input_len > 0) return 0;
    return checksum_file_prefix(input, input_len);
}

#ifndef LAB_CRYPTO_DLL_ONLY
static void print_usage(const char* exe) {
    std::cout << "Usage:\n"
              << "  " << exe << " info\n"
              << "  " << exe << " keygen --algo <ecdsa-p256|ecdsa-p384|rsa-pss-3072> --priv <priv.pem> --pub <pub.pem>\n"
              << "  " << exe << " sign   --algo <ecdsa-p256|ecdsa-p384|rsa-pss-3072> --priv <priv.pem> --in <msg.bin> --out <sig.bin>\n"
              << "  " << exe << " verify --algo <ecdsa-p256|ecdsa-p384|rsa-pss-3072> --pub <pub.pem> --in <msg.bin> --sig <sig.bin>\n"
              << "  " << exe << " --kat  <nist_vectors.json>\n";
}

static std::string extract_json_string(const std::string& json, const std::string& key, size_t start_pos = 0) {
    size_t pos = json.find("\"" + key + "\"", start_pos);
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

static bool run_kat(const std::string& kat_file) {
    std::vector<unsigned char> data;
    try {
        data = read_file(kat_file);
    } catch(...) {
        std::cerr << "Failed to read KAT file\n";
        return false;
    }
    std::string json(data.begin(), data.end());
    
    std::string algo = extract_json_string(json, "algo");
    std::string msg_file = extract_json_string(json, "msg");
    std::string sig_file = extract_json_string(json, "sig");
    std::string pub_file = extract_json_string(json, "pub");
    
    std::cout << "KAT parsed. Algo: " << algo << "\n";
    if (algo.empty() || msg_file.empty() || sig_file.empty() || pub_file.empty()) {
        std::cerr << "KAT JSON is missing fields.\n";
        return false;
    }

    std::filesystem::path kat_dir = std::filesystem::path(kat_file).parent_path();
    if (kat_dir.empty()) kat_dir = ".";
    
    std::string msg_path = (kat_dir / msg_file).string();
    std::string sig_path = (kat_dir / sig_file).string();
    std::string pub_path = (kat_dir / pub_file).string();

    bool ok = false;
    if (algo == "ecdsa-p256") {
        ok = verify_ecdsa(pub_path.c_str(), msg_path.c_str(), sig_path.c_str());
    } else if (algo == "ecdsa-p384") {
        ok = verify_ecdsa_p384(pub_path.c_str(), msg_path.c_str(), sig_path.c_str());
    } else if (algo == "rsa-pss-3072") {
        ok = verify_rsapss(pub_path.c_str(), msg_path.c_str(), sig_path.c_str());
    } else {
        std::cerr << "Unsupported KAT algo: " << algo << "\n";
        return false;
    }

    if (!ok) {
        if (get_last_error()[0] != '\0') std::cout << "Error: " << get_last_error() << "\n";
    }

    std::cout << "KAT " << (ok ? "PASSED" : "FAILED") << "\n";
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "info") {
        std::cout << lab_crypto_name() << "\n";
        std::cout << "Version: " << lab_crypto_version() << "\n";
        std::cout << "Libraries: OpenSSL EVP keygen/DigestSign/DigestVerify\n";
        return 0;
    }

    if (cmd == "--kat" && argc == 3) {
        return run_kat(argv[2]) ? 0 : 1;
    }

    std::string algo, priv, pub, in_file, out_file, sig_file, hash_algo;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc) algo = argv[++i];
        else if (arg == "--priv" && i + 1 < argc) priv = argv[++i];
        else if (arg == "--pub" && i + 1 < argc) pub = argv[++i];
        else if (arg == "--in" && i + 1 < argc) in_file = argv[++i];
        else if (arg == "--out" && i + 1 < argc) out_file = argv[++i];
        else if (arg == "--sig" && i + 1 < argc) sig_file = argv[++i];
        else if (arg == "--hash" && i + 1 < argc) hash_algo = argv[++i];
    }

    if (cmd == "keygen") {
        if (algo.empty() || priv.empty() || pub.empty()) {
            std::cerr << "Error: keygen requires --algo, --priv, --pub\n";
            return 1;
        }
        bool ok = false;
        if (algo == "ecdsa-p256") ok = generate_ecdsa_keypair("prime256v1", priv.c_str(), pub.c_str());
        else if (algo == "ecdsa-p384") ok = generate_ecdsa_keypair("secp384r1", priv.c_str(), pub.c_str());
        else if (algo == "rsa-pss-3072") ok = generate_rsa_keypair(3072, priv.c_str(), pub.c_str());
        else std::cerr << "Unsupported algo: " << algo << "\n";
        if (ok) return 0;
    } 
    else if (cmd == "sign") {
        if (algo.empty() || priv.empty() || in_file.empty() || out_file.empty()) {
            std::cerr << "Error: sign requires --algo, --priv, --in, --out\n";
            return 1;
        }
        bool ok = false;
        if (algo == "ecdsa-p256") ok = sign_ecdsa(priv.c_str(), in_file.c_str(), out_file.c_str());
        else if (algo == "ecdsa-p384") ok = sign_ecdsa_p384(priv.c_str(), in_file.c_str(), out_file.c_str());
        else if (algo == "rsa-pss-3072") ok = sign_rsapss(priv.c_str(), in_file.c_str(), out_file.c_str());
        else std::cerr << "Unsupported algo: " << algo << "\n";
        if (ok) return 0;
    }
    else if (cmd == "verify") {
        if (algo.empty() || pub.empty() || in_file.empty() || sig_file.empty()) {
            std::cerr << "Error: verify requires --algo, --pub, --in, --sig\n";
            return 1;
        }
        bool ok = false;
        if (algo == "ecdsa-p256") ok = verify_ecdsa(pub.c_str(), in_file.c_str(), sig_file.c_str());
        else if (algo == "ecdsa-p384") ok = verify_ecdsa_p384(pub.c_str(), in_file.c_str(), sig_file.c_str());
        else if (algo == "rsa-pss-3072") ok = verify_rsapss(pub.c_str(), in_file.c_str(), sig_file.c_str());
        else std::cerr << "Unsupported algo: " << algo << "\n";
        
        std::cout << (ok ? "VERIFY OK" : "VERIFY FAILED") << "\n";
        return ok ? 0 : 4;
    }

    if (get_last_error()[0] != '\0') {
        std::cerr << "Error: " << get_last_error() << "\n";
    } else {
        print_usage(argv[0]);
    }
    return 1;
}
#endif
