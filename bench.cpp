#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <filesystem>

extern "C" bool generate_ecdsa_keypair(const char* curve_name, const char* private_key_path, const char* public_key_path) noexcept;
extern "C" bool generate_rsa_keypair(int bits, const char* private_key_path, const char* public_key_path) noexcept;
extern "C" bool sign_ecdsa(const char* private_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool sign_rsapss(const char* private_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool verify_ecdsa(const char* public_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool verify_rsapss(const char* public_key_path, const char* message_path, const char* signature_path) noexcept;

// Khai bao them ham P-384
extern "C" bool sign_ecdsa_p384(const char* private_key_path, const char* message_path, const char* signature_path) noexcept;
extern "C" bool verify_ecdsa_p384(const char* public_key_path, const char* message_path, const char* signature_path) noexcept;

using namespace std;
using Clock = chrono::high_resolution_clock;

const int N_WARMUP = 5;
const int N_RUNS = 30;

struct RawSample {
    string operation;
    string algo;
    string size_label;
    size_t payload_bytes;
    int run_index;
    double time_ms;
};

struct Stats {
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci95_ms;
    double throughput_MBs;
    size_t payload;
};

static Stats ComputeStats(vector<double>& samples_ms, size_t payload_bytes) {
    int n = (int)samples_ms.size();
    sort(samples_ms.begin(), samples_ms.end());

    double sum = accumulate(samples_ms.begin(), samples_ms.end(), 0.0);
    double mean = sum / n;

    double var = 0;
    for (auto v : samples_ms) var += (v - mean) * (v - mean);
    var /= (n - 1);
    double sd = sqrt(var);

    double median = (n % 2 == 0)
        ? (samples_ms[n/2-1] + samples_ms[n/2]) / 2.0
        : samples_ms[n/2];

    double t95 = (n >= 30) ? 2.042 : 2.776;
    double ci  = t95 * sd / sqrt((double)n);

    double throughput = 0;
    if (payload_bytes > 0 && mean > 0) {
        throughput = (payload_bytes / 1e6) / (mean / 1e3);
    }

    return {mean, median, sd, ci, throughput, payload_bytes};
}

static void create_file(const string& path, size_t size) {
    ofstream f(path, ios::binary);
    vector<char> data(size, 'A');
    f.write(data.data(), size);
}

static void WriteRawCSV(const string& path, const vector<RawSample>& rows) {
    ofstream f(path);
    f << "operation,algo,size_label,payload_bytes,run_index,time_ms\n";
    for (const auto& r : rows) {
        f << r.operation << ","
          << r.algo << ","
          << r.size_label << ","
          << r.payload_bytes << ","
          << r.run_index << ","
          << fixed << setprecision(6) << r.time_ms << "\n";
    }
}

int main(int argc, char* argv[]) {
    string summary_csv = "summary.csv";
    string raw_csv = "benchmark_raw.csv";

    for (int i = 1; i < argc; ++i) {
        if (string(argv[i]) == "--csv" && i + 1 < argc) summary_csv = argv[++i];
        if (string(argv[i]) == "--rawcsv" && i + 1 < argc) raw_csv = argv[++i];
    }

    vector<pair<string, size_t>> sizes = {
        {"1 KB", 1024},
        {"16 KB", 16 * 1024},
        {"1 MB", 1024 * 1024},
        {"8 MB", 8 * 1024 * 1024}
    };

    // DA BO SUNG ecdsa-p384 vao danh sach
    vector<string> algos = {"ecdsa-p256", "ecdsa-p384", "rsa-pss-3072"};
    vector<RawSample> raw_data;
    vector<tuple<string, string, string, Stats>> summary_rows;

    const string priv_file = "temp_priv.pem";
    const string pub_file = "temp_pub.pem";
    const string msg_file = "temp_msg.bin";
    const string sig_file = "temp_sig.bin";

    cout << "Starting benchmark (N=" << N_RUNS << ")...\n";

    for (const auto& algo : algos) {
        for (const auto& [size_label, size_bytes] : sizes) {
            cout << "Benchmarking " << algo << " at " << size_label << "...\n";
            create_file(msg_file, size_bytes);

            // 1. Benchmark Keygen
            cout << "  -> Keygen (Warmup: " << N_WARMUP << ", Benchmark: " << N_RUNS << ")...\n";
            vector<double> keygen_samples;
            
            // Warm-up
            for (int i = 0; i < N_WARMUP; ++i) {
                if (algo == "ecdsa-p256") generate_ecdsa_keypair("prime256v1", priv_file.c_str(), pub_file.c_str());
                else if (algo == "ecdsa-p384") generate_ecdsa_keypair("secp384r1", priv_file.c_str(), pub_file.c_str());
                else generate_rsa_keypair(3072, priv_file.c_str(), pub_file.c_str());
            }

            // Timed runs
            for (int i = 0; i < N_RUNS; ++i) {
                auto t0 = Clock::now();
                if (algo == "ecdsa-p256") generate_ecdsa_keypair("prime256v1", priv_file.c_str(), pub_file.c_str());
                else if (algo == "ecdsa-p384") generate_ecdsa_keypair("secp384r1", priv_file.c_str(), pub_file.c_str());
                else generate_rsa_keypair(3072, priv_file.c_str(), pub_file.c_str());
                auto t1 = Clock::now();
                double ms = chrono::duration<double, milli>(t1 - t0).count();
                keygen_samples.push_back(ms);
                raw_data.push_back({"keygen", algo, size_label, size_bytes, i + 1, ms});
            }
            summary_rows.push_back({algo, "keygen", size_label, ComputeStats(keygen_samples, 0)});

            // Make sure we have a valid key for sign/verify
            if (algo == "ecdsa-p256") generate_ecdsa_keypair("prime256v1", priv_file.c_str(), pub_file.c_str());
            else if (algo == "ecdsa-p384") generate_ecdsa_keypair("secp384r1", priv_file.c_str(), pub_file.c_str());
            else generate_rsa_keypair(3072, priv_file.c_str(), pub_file.c_str());

            // 2. Benchmark Sign
            cout << "  -> Sign   (Warmup: " << N_WARMUP << ", Benchmark: " << N_RUNS << ")...\n";
            vector<double> sign_samples;
            
            // Warm-up
            for (int i = 0; i < N_WARMUP; ++i) {
                if (algo == "ecdsa-p256") sign_ecdsa(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else if (algo == "ecdsa-p384") sign_ecdsa_p384(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else sign_rsapss(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
            }

            // Timed runs
            for (int i = 0; i < N_RUNS; ++i) {
                auto t0 = Clock::now();
                if (algo == "ecdsa-p256") sign_ecdsa(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else if (algo == "ecdsa-p384") sign_ecdsa_p384(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else sign_rsapss(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
                auto t1 = Clock::now();
                double ms = chrono::duration<double, milli>(t1 - t0).count();
                sign_samples.push_back(ms);
                raw_data.push_back({"sign", algo, size_label, size_bytes, i + 1, ms});
            }
            summary_rows.push_back({algo, "sign", size_label, ComputeStats(sign_samples, size_bytes)});

            // 3. Benchmark Verify
            // Ensure we have a valid signature
            if (algo == "ecdsa-p256") sign_ecdsa(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
            else if (algo == "ecdsa-p384") sign_ecdsa_p384(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());
            else sign_rsapss(priv_file.c_str(), msg_file.c_str(), sig_file.c_str());

            cout << "  -> Verify (Warmup: " << N_WARMUP << ", Benchmark: " << N_RUNS << ")...\n";
            vector<double> verify_samples;

            // Warm-up
            for (int i = 0; i < N_WARMUP; ++i) {
                if (algo == "ecdsa-p256") verify_ecdsa(pub_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else if (algo == "ecdsa-p384") verify_ecdsa_p384(pub_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else verify_rsapss(pub_file.c_str(), msg_file.c_str(), sig_file.c_str());
            }

            // Timed runs
            for (int i = 0; i < N_RUNS; ++i) {
                auto t0 = Clock::now();
                if (algo == "ecdsa-p256") verify_ecdsa(pub_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else if (algo == "ecdsa-p384") verify_ecdsa_p384(pub_file.c_str(), msg_file.c_str(), sig_file.c_str());
                else verify_rsapss(pub_file.c_str(), msg_file.c_str(), sig_file.c_str());
                auto t1 = Clock::now();
                double ms = chrono::duration<double, milli>(t1 - t0).count();
                verify_samples.push_back(ms);
                raw_data.push_back({"verify", algo, size_label, size_bytes, i + 1, ms});
            }
            summary_rows.push_back({algo, "verify", size_label, ComputeStats(verify_samples, size_bytes)});
        }
    }

    // Write Summary CSV
    ofstream f_sum(summary_csv);
    f_sum << "algo,operation,size_label,payload_bytes,mean_ms,median_ms,stddev_ms,ci95_ms,throughput_MBs\n";
    for (auto& [algo, op, label, s] : summary_rows) {
        f_sum << algo << "," << op << "," << label << "," << s.payload << ","
              << fixed << setprecision(4) << s.mean_ms << "," << s.median_ms << ","
              << s.stddev_ms << "," << s.ci95_ms << "," << s.throughput_MBs << "\n";
    }

    WriteRawCSV(raw_csv, raw_data);

    // Cleanup
    error_code ec;
    filesystem::remove(priv_file, ec);
    filesystem::remove(pub_file, ec);
    filesystem::remove(msg_file, ec);
    filesystem::remove(sig_file, ec);

    cout << "Done! Results written to " << summary_csv << " and " << raw_csv << "\n";
    return 0;
}
