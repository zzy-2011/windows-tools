/*
 * NetGuard v2.0 - 网络后门检测工具 (GUI 版)
 *
 * 功能:
 *   1. Win32 原生 GUI 界面，ListView 彩色分级展示连接
 *   2. 枚举系统所有 TCP 连接及其关联进程
 *   3. 多维度风险评估 (端口/黑名单/路径/系统进程/AbuseIPDB)
 *   4. 从 Emerging Threats / Blocklist.de / Feodo Tracker 在线获取 IP 黑名单
 *   5. 可选 AbuseIPDB API 查询 IP 信誉
 *   6. 支持导出文本报告
 *
 * 编译 (MinGW):
 *   g++ -std=c++17 -O2 -mwindows -o NetGuard.exe main.cpp netguard.rc
 *       -liphlpapi -lpsapi -lws2_32 -lwinhttp -lcomctl32
 */

#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winhttp.h>

#include <string>
#include <vector>
#include <set>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <process.h>

#include "resource.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comctl32.lib")

// ================================================================
//  Forward Declarations
// ================================================================
LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SettingsWndProc(HWND, UINT, WPARAM, LPARAM);
unsigned __stdcall ScanThreadProc(void*);
unsigned __stdcall BlacklistDownloadProc(void*);
unsigned __stdcall AbuseQueryProc(void*);

// ================================================================
//  Risk Levels
// ================================================================
enum RiskLevel {
    RISK_SAFE = 0, RISK_LOW = 1, RISK_MEDIUM = 2,
    RISK_HIGH = 3, RISK_CRITICAL = 4
};

static const wchar_t* RiskNameW(RiskLevel r) {
    switch (r) {
        case RISK_SAFE:     return L"\x5B89\x5168";   // 安全
        case RISK_LOW:      return L"\x4F4E\x5371";   // 低危
        case RISK_MEDIUM:   return L"\x4E2D\x5371";   // 中危
        case RISK_HIGH:     return L"\x9AD8\x5371";   // 高危
        case RISK_CRITICAL: return L"\x4E25\x91CD";   // 严重
        default:            return L"?";
    }
}

static const char* RiskNameA(RiskLevel r) {
    switch (r) {
        case RISK_SAFE:     return "SAFE";
        case RISK_LOW:      return "LOW";
        case RISK_MEDIUM:   return "MEDIUM";
        case RISK_HIGH:     return "HIGH";
        case RISK_CRITICAL: return "CRITICAL";
        default:            return "?";
    }
}

static COLORREF RiskTextColor(RiskLevel r) {
    switch (r) {
        case RISK_SAFE:     return RGB(34, 120, 34);
        case RISK_LOW:      return RGB(0, 100, 120);
        case RISK_MEDIUM:   return RGB(160, 110, 0);
        case RISK_HIGH:     return RGB(200, 30, 30);
        case RISK_CRITICAL: return RGB(255, 255, 255);
        default:            return RGB(0, 0, 0);
    }
}

static COLORREF RiskBgColor(RiskLevel r) {
    switch (r) {
        case RISK_SAFE:     return RGB(255, 255, 255);
        case RISK_LOW:      return RGB(232, 248, 248);
        case RISK_MEDIUM:   return RGB(255, 250, 220);
        case RISK_HIGH:     return RGB(255, 225, 225);
        case RISK_CRITICAL: return RGB(170, 30, 30);
        default:            return RGB(255, 255, 255);
    }
}

// ================================================================
//  Data Structures
// ================================================================
struct ConnectionInfo {
    DWORD       pid;
    std::string processName;
    std::string processPath;
    std::string localAddr;
    DWORD       localPort;
    std::string remoteAddr;
    DWORD       remotePort;
    std::string state;
    RiskLevel   risk;
    std::vector<std::string> reasons;
};

struct PortInfo {
    const char* description;
    RiskLevel   defaultRisk;
};

struct AppSettings {
    std::wstring abuseApiKey;
    bool abuseEnabled   = false;
    bool srcET          = true;
    bool srcBlocklist   = true;
    bool srcFeodo       = true;
    int  cacheTtlHours  = 24;
};

struct AbuseResult {
    int         score        = 0;
    std::string country;
    std::string isp;
    int         totalReports = 0;
    time_t      queriedAt    = 0;
};

struct AppState {
    HINSTANCE hInstance = NULL;
    HFONT     hFont    = NULL;

    HWND hwndMain      = NULL;
    HWND hwndListView  = NULL;
    HWND hwndStatusBar = NULL;
    HWND hwndProgress  = NULL;
    HWND hwndBtnScan   = NULL;
    HWND hwndBtnStop   = NULL;
    HWND hwndBtnExport = NULL;
    HWND hwndBtnBL     = NULL;
    HWND hwndBtnSet    = NULL;
    HWND hwndCombo     = NULL;

    HANDLE hScanThread  = NULL;
    HANDLE hBlThread    = NULL;
    HANDLE hAbuseThread = NULL;

    std::atomic<bool> cancelScan{false};
    std::atomic<bool> scanning{false};
    std::atomic<bool> downloadingBl{false};

    std::vector<ConnectionInfo> results;
    int currentFilter = 0;

    CRITICAL_SECTION csBlacklist;
    CRITICAL_SECTION csAbuseCache;

    AppSettings settings;
};

// ================================================================
//  Global State
// ================================================================
static AppState g_app;
static std::set<std::string>          g_blacklist;
static std::map<std::string, AbuseResult> g_abuseCache;

// ================================================================
//  Suspicious Port Database
// ================================================================
static const std::map<DWORD, PortInfo> SUSPICIOUS_PORTS = {
    {4444,  {"Metasploit",        RISK_HIGH}},
    {5555,  {"RAT",               RISK_HIGH}},
    {6666,  {"Backdoor",          RISK_HIGH}},
    {7777,  {"Backdoor",          RISK_MEDIUM}},
    {9999,  {"Backdoor",          RISK_MEDIUM}},
    {1234,  {"Test/Backdoor",     RISK_MEDIUM}},
    {1337,  {"Leet",              RISK_HIGH}},
    {31337, {"Back Orifice",      RISK_CRITICAL}},
    {12345, {"NetBus",            RISK_CRITICAL}},
    {54321, {"BO2K",              RISK_CRITICAL}},
    {27374, {"SubSeven",          RISK_CRITICAL}},
    {6667,  {"IRC C2",            RISK_HIGH}},
    {6668,  {"IRC C2",            RISK_HIGH}},
    {6669,  {"IRC C2",            RISK_HIGH}},
    {23,    {"Telnet",            RISK_MEDIUM}},
    {2323,  {"Alt Telnet",        RISK_MEDIUM}},
    {5900,  {"VNC",               RISK_MEDIUM}},
    {5901,  {"VNC",               RISK_MEDIUM}},
    {4443,  {"Alt HTTPS/C2",      RISK_MEDIUM}},
    {1080,  {"SOCKS Proxy",       RISK_LOW}},
    {3128,  {"HTTP Proxy",        RISK_LOW}},
    {9050,  {"Tor SOCKS",         RISK_HIGH}},
    {9051,  {"Tor Control",       RISK_HIGH}},
    {3389,  {"RDP",               RISK_LOW}},
    {8888,  {"Alt HTTP",          RISK_LOW}},
    {4782,  {"Bifrost",           RISK_CRITICAL}},
    {5000,  {"Debug/Backdoor",    RISK_MEDIUM}},
    {65535, {"Max Port",          RISK_MEDIUM}},
};

static const std::vector<std::string> SUSPICIOUS_PATH_KEYWORDS = {
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "$recycle.bin", "\\users\\public\\",
};

static const std::set<std::string> KNOWN_SYSTEM_PROCS = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe",
    "winlogon.exe", "wininit.exe", "services.exe", "spoolsv.exe",
    "dwm.exe", "taskhost.exe", "taskhostw.exe",
};

// ================================================================
//  Utility Functions
// ================================================================
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (n <= 0) return L"";
    std::wstring ws(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], n);
    return ws;
}

static std::string WideToUtf8(const std::wstring& ws) {
    if (ws.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, NULL, 0, NULL, NULL);
    if (n <= 0) return "";
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], n, NULL, NULL);
    return s;
}

static std::wstring GetExeDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring p(path);
    size_t pos = p.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? p.substr(0, pos + 1) : L"";
}

static std::string IpToStr(DWORD dwAddr) {
    struct in_addr addr;
    addr.s_addr = dwAddr;
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

static std::string StateName(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED:      return "CLOSED";
        case MIB_TCP_STATE_LISTEN:      return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:     return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        default:                        return "UNKNOWN";
    }
}

static bool IsPrivateIP(const std::string& ip) {
    if (ip == "0.0.0.0" || ip.rfind("127.", 0) == 0) return true;
    if (ip.rfind("10.", 0) == 0) return true;
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip.rfind("172.", 0) == 0) {
        size_t dot = ip.find('.', 4);
        if (dot != std::string::npos) {
            int o = std::atoi(ip.substr(4, dot - 4).c_str());
            if (o >= 16 && o <= 31) return true;
        }
    }
    return false;
}

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string ReverseDNS(const std::string& ip) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[NI_MAXHOST] = {0};
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                    host, sizeof(host), NULL, 0, 0) == 0) {
        std::string h(host);
        if (h != ip) return h;
    }
    return "";
}

static bool IsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID grp = NULL;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(NULL, grp, &isAdmin);
        FreeSid(grp);
    }
    return isAdmin != FALSE;
}

static bool IsValidIPv4(const std::string& s) {
    int dots = 0, val = 0;
    bool hasDigit = false;
    for (char c : s) {
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return false;
            hasDigit = true;
        } else if (c == '.') {
            if (!hasDigit) return false;
            dots++;
            val = 0;
            hasDigit = false;
        } else {
            return false;
        }
    }
    return hasDigit && dots == 3;
}

// ================================================================
//  Process Map Builder
// ================================================================
static std::map<DWORD, std::pair<std::string, std::string>> BuildProcessMap() {
    std::map<DWORD, std::pair<std::string, std::string>> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            std::string path;
            HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    FALSE, pe.th32ProcessID);
            if (hp) {
                char buf[MAX_PATH] = {0};
                if (GetModuleFileNameExA(hp, NULL, buf, MAX_PATH))
                    path = buf;
                CloseHandle(hp);
            }
            procs[pe.th32ProcessID] = {name, path};
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return procs;
}

// ================================================================
//  Risk Assessment
// ================================================================
static void AssessRisk(ConnectionInfo& c) {
    c.risk = RISK_SAFE;
    c.reasons.clear();

    bool isEstablished = (c.state == "ESTABLISHED");
    bool isListening   = (c.state == "LISTEN");
    bool isExternal    = !IsPrivateIP(c.remoteAddr);

    // 1. Blacklisted IP
    {
        EnterCriticalSection(&g_app.csBlacklist);
        bool hit = !c.remoteAddr.empty() && g_blacklist.count(c.remoteAddr);
        LeaveCriticalSection(&g_app.csBlacklist);
        if (hit) {
            c.risk = RISK_CRITICAL;
            c.reasons.push_back("[Blacklist] IP in threat list");
        }
    }

    // 2. Remote port suspicious
    if (c.remotePort > 0) {
        auto it = SUSPICIOUS_PORTS.find(c.remotePort);
        if (it != SUSPICIOUS_PORTS.end()) {
            if (it->second.defaultRisk > c.risk) c.risk = it->second.defaultRisk;
            c.reasons.push_back(std::string("[Port] Remote ") +
                std::to_string(c.remotePort) + " - " + it->second.description);
        }
    }

    // 3. Listening on suspicious port
    if (isListening) {
        auto it = SUSPICIOUS_PORTS.find(c.localPort);
        if (it != SUSPICIOUS_PORTS.end()) {
            if (it->second.defaultRisk > c.risk) c.risk = it->second.defaultRisk;
            c.reasons.push_back(std::string("[Listen] Port ") +
                std::to_string(c.localPort) + " - " + it->second.description);
        }
    }

    // 4. Suspicious process path
    if (!c.processPath.empty()) {
        std::string lp = ToLower(c.processPath);
        for (const auto& kw : SUSPICIOUS_PATH_KEYWORDS) {
            if (lp.find(kw) != std::string::npos) {
                if (RISK_MEDIUM > c.risk) c.risk = RISK_MEDIUM;
                c.reasons.push_back("[Path] Suspicious directory");
                break;
            }
        }
    }

    // 5. System process external connection
    if (isEstablished && isExternal) {
        if (KNOWN_SYSTEM_PROCS.count(ToLower(c.processName))) {
            if (RISK_LOW > c.risk) c.risk = RISK_LOW;
            c.reasons.push_back("[System] " + c.processName + " -> external");
        }
    }

    // 6. Non-standard external port
    if (isEstablished && isExternal && c.remotePort > 0) {
        static const std::set<DWORD> common = {
            22, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 8080, 8443
        };
        if (!common.count(c.remotePort) && !SUSPICIOUS_PORTS.count(c.remotePort)) {
            if (RISK_LOW > c.risk) c.risk = RISK_LOW;
            c.reasons.push_back("[Port] Non-standard " + std::to_string(c.remotePort));
        }
    }

    // 7. SYN_SENT to external
    if (c.state == "SYN_SENT" && isExternal) {
        if (RISK_LOW > c.risk) c.risk = RISK_LOW;
        c.reasons.push_back("[Conn] Outbound SYN");
    }

    // 8. Reverse DNS for medium+
    if (c.risk >= RISK_MEDIUM && isExternal && !c.remoteAddr.empty()
        && c.remoteAddr != "0.0.0.0") {
        std::string dns = ReverseDNS(c.remoteAddr);
        if (!dns.empty())
            c.reasons.push_back("[DNS] " + dns);
    }

    // 9. AbuseIPDB cache hit
    if (isExternal && !c.remoteAddr.empty()) {
        EnterCriticalSection(&g_app.csAbuseCache);
        auto it = g_abuseCache.find(c.remoteAddr);
        if (it != g_abuseCache.end()) {
            auto& ar = it->second;
            if (ar.score > 75) {
                if (RISK_CRITICAL > c.risk) c.risk = RISK_CRITICAL;
            } else if (ar.score > 30) {
                if (RISK_HIGH > c.risk) c.risk = RISK_HIGH;
            }
            c.reasons.push_back("[AbuseIPDB] Score:" + std::to_string(ar.score) +
                " Reports:" + std::to_string(ar.totalReports) +
                " Country:" + ar.country);
        }
        LeaveCriticalSection(&g_app.csAbuseCache);
    }
}

// ================================================================
//  TCP Scanner
// ================================================================
static std::vector<ConnectionInfo> ScanTcpConnections(
    const std::map<DWORD, std::pair<std::string, std::string>>& procMap)
{
    std::vector<ConnectionInfo> results;
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return results;

    std::vector<BYTE> buffer(size);
    auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return results;

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        if (g_app.cancelScan) break;
        const auto& row = tcpTable->table[i];
        ConnectionInfo ci;
        ci.pid        = row.dwOwningPid;
        ci.localAddr  = IpToStr(row.dwLocalAddr);
        ci.localPort  = ntohs(static_cast<u_short>(row.dwLocalPort));
        ci.remoteAddr = IpToStr(row.dwRemoteAddr);
        ci.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
        ci.state      = StateName(row.dwState);

        auto it = procMap.find(ci.pid);
        if (it != procMap.end()) {
            ci.processName = it->second.first;
            ci.processPath = it->second.second;
        } else {
            ci.processName = "<unknown>";
        }
        AssessRisk(ci);
        results.push_back(ci);
    }
    return results;
}

// ================================================================
//  Blacklist Management (Local File)
// ================================================================
static bool LoadBlacklistFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    int n = 0;
    while (std::getline(f, line)) {
        size_t s = line.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) continue;
        size_t e = line.find_last_not_of(" \t\r\n");
        line = line.substr(s, e - s + 1);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (IsValidIPv4(line)) {
            EnterCriticalSection(&g_app.csBlacklist);
            g_blacklist.insert(line);
            LeaveCriticalSection(&g_app.csBlacklist);
            n++;
        }
    }
    return n > 0;
}

static std::wstring GetCacheDir() {
    std::wstring dir = GetExeDir() + L"netguard_cache";
    CreateDirectoryW(dir.c_str(), NULL);
    return dir + L"\\";
}

static void SaveBlacklistCache(const std::wstring& name,
                               const std::set<std::string>& ips) {
    std::wstring path = GetCacheDir() + name + L".txt";
    std::ofstream f(WideToUtf8(path));
    if (!f.is_open()) return;
    time_t now = time(nullptr);
    f << "# NetGuard Cache\n# Timestamp: " << now << "\n";
    for (const auto& ip : ips) f << ip << "\n";
}

static bool LoadBlacklistCache(const std::wstring& name) {
    std::wstring path = GetCacheDir() + name + L".txt";
    std::ifstream f(WideToUtf8(path));
    if (!f.is_open()) return false;

    std::string line;
    time_t cacheTime = 0;
    int count = 0;
    while (std::getline(f, line)) {
        if (line.rfind("# Timestamp: ", 0) == 0) {
            cacheTime = (time_t)std::stoll(line.substr(13));
            time_t age = time(nullptr) - cacheTime;
            if (g_app.settings.cacheTtlHours < 99999 &&
                age > g_app.settings.cacheTtlHours * 3600)
                return false; // Expired
            continue;
        }
        if (line.empty() || line[0] == '#') continue;
        size_t s = line.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) continue;
        size_t e = line.find_last_not_of(" \t\r\n");
        line = line.substr(s, e - s + 1);
        if (IsValidIPv4(line)) {
            EnterCriticalSection(&g_app.csBlacklist);
            g_blacklist.insert(line);
            LeaveCriticalSection(&g_app.csBlacklist);
            count++;
        }
    }
    return count > 0;
}

// ================================================================
//  WinHTTP Helper
// ================================================================
static std::string HttpGet(const std::wstring& host, const std::wstring& path,
                           INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT,
                           const std::wstring& extraHeaders = L"")
{
    std::string result;
    HINTERNET hSession = WinHttpOpen(L"NetGuard/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;

    DWORD timeout = 20000;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return result; }

    DWORD flags = (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) {
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
        return result;
    }

    if (!extraHeaders.empty())
        WinHttpAddRequestHeaders(hReq, extraHeaders.c_str(), -1,
                                 WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD avail, bytesRead;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        if (WinHttpReadData(hReq, buf.data(), avail, &bytesRead))
            result.append(buf.data(), bytesRead);
        else break;
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return result;
}

// ================================================================
//  AbuseIPDB Minimal JSON Parser
// ================================================================
static int ExtractJsonInt(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    while (pos < json.size() && json[pos] == ' ') pos++;
    std::string num;
    while (pos < json.size() && (json[pos] >= '0' && json[pos] <= '9'))
        num += json[pos++];
    return num.empty() ? 0 : std::stoi(num);
}

static std::string ExtractJsonStr(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    size_t end = json.find('"', pos);
    return (end != std::string::npos) ? json.substr(pos, end - pos) : "";
}

// ================================================================
//  Thread Functions
// ================================================================
unsigned __stdcall ScanThreadProc(void* param) {
    HWND hwnd = (HWND)param;
    auto procMap = BuildProcessMap();
    auto connections = ScanTcpConnections(procMap);

    if (g_app.cancelScan) {
        g_app.scanning = false;
        return 0;
    }

    std::sort(connections.begin(), connections.end(),
        [](const ConnectionInfo& a, const ConnectionInfo& b) {
            return a.risk > b.risk;
        });

    auto* pResults = new std::vector<ConnectionInfo>(std::move(connections));
    PostMessage(hwnd, WM_SCAN_COMPLETE, 0, (LPARAM)pResults);
    g_app.scanning = false;
    return 0;
}

unsigned __stdcall BlacklistDownloadProc(void* param) {
    HWND hwnd = (HWND)param;

    struct Source {
        const wchar_t* name;
        const wchar_t* host;
        const wchar_t* path;
        bool enabled;
    };
    Source sources[] = {
        {L"emerging_threats", L"rules.emergingthreats.net",
         L"/blockrules/compromised-ips.txt", g_app.settings.srcET},
        {L"blocklist_de", L"www.blocklist.de",
         L"/downloads/export-ips_all.txt", g_app.settings.srcBlocklist},
        {L"feodo_tracker", L"feodotracker.abuse.ch",
         L"/downloads/ipblocklist.txt", g_app.settings.srcFeodo},
    };

    int totalLoaded = 0;
    for (auto& src : sources) {
        if (g_app.cancelScan) break;
        if (!src.enabled) continue;

        // Try cache first
        if (LoadBlacklistCache(src.name)) {
            EnterCriticalSection(&g_app.csBlacklist);
            totalLoaded = (int)g_blacklist.size();
            LeaveCriticalSection(&g_app.csBlacklist);
            continue;
        }

        // Download
        std::string body = HttpGet(src.host, src.path);
        if (body.empty()) continue;

        std::set<std::string> ips;
        std::istringstream iss(body);
        std::string line;
        while (std::getline(iss, line)) {
            size_t s = line.find_first_not_of(" \t\r\n");
            if (s == std::string::npos) continue;
            size_t e = line.find_last_not_of(" \t\r\n");
            line = line.substr(s, e - s + 1);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            if (IsValidIPv4(line))
                ips.insert(line);
        }

        if (!ips.empty()) {
            EnterCriticalSection(&g_app.csBlacklist);
            g_blacklist.insert(ips.begin(), ips.end());
            totalLoaded = (int)g_blacklist.size();
            LeaveCriticalSection(&g_app.csBlacklist);
            SaveBlacklistCache(src.name, ips);
        }
    }

    PostMessage(hwnd, WM_BL_COMPLETE, (WPARAM)totalLoaded, 0);
    g_app.downloadingBl = false;
    return 0;
}

unsigned __stdcall AbuseQueryProc(void* param) {
    HWND hwnd = (HWND)param;

    // Collect unique external IPs with risk >= MEDIUM
    std::set<std::string> toQuery;
    for (const auto& c : g_app.results) {
        if (c.risk >= RISK_MEDIUM && !IsPrivateIP(c.remoteAddr)
            && c.remoteAddr != "0.0.0.0") {
            EnterCriticalSection(&g_app.csAbuseCache);
            bool cached = g_abuseCache.count(c.remoteAddr) > 0;
            LeaveCriticalSection(&g_app.csAbuseCache);
            if (!cached) toQuery.insert(c.remoteAddr);
        }
    }

    int queried = 0;
    for (const auto& ip : toQuery) {
        if (g_app.cancelScan) break;
        if (queried >= 20) break; // Limit per scan

        std::wstring path = L"/api/v2/check?ipAddress=" + Utf8ToWide(ip) +
                            L"&maxAgeInDays=90";
        std::wstring headers = L"Key: " + g_app.settings.abuseApiKey +
                               L"\r\nAccept: application/json\r\n";
        std::string body = HttpGet(L"api.abuseipdb.com", path,
                                   INTERNET_DEFAULT_HTTPS_PORT, headers);
        if (!body.empty()) {
            AbuseResult ar;
            ar.score        = ExtractJsonInt(body, "abuseConfidenceScore");
            ar.country      = ExtractJsonStr(body, "countryCode");
            ar.isp          = ExtractJsonStr(body, "isp");
            ar.totalReports = ExtractJsonInt(body, "totalReports");
            ar.queriedAt    = time(nullptr);

            EnterCriticalSection(&g_app.csAbuseCache);
            g_abuseCache[ip] = ar;
            LeaveCriticalSection(&g_app.csAbuseCache);
        }

        queried++;
        Sleep(1500); // Rate limiting
    }

    // Signal GUI to re-assess risks
    if (queried > 0)
        PostMessage(hwnd, WM_ABUSE_RESULT, (WPARAM)queried, 0);
    return 0;
}

// ================================================================
//  Settings I/O
// ================================================================
static std::wstring GetIniPath() { return GetExeDir() + L"netguard.ini"; }

static void LoadSettings() {
    std::wstring ini = GetIniPath();
    wchar_t buf[512];
    GetPrivateProfileStringW(L"AbuseIPDB", L"ApiKey", L"", buf, 512, ini.c_str());
    g_app.settings.abuseApiKey = buf;
    g_app.settings.abuseEnabled =
        GetPrivateProfileIntW(L"AbuseIPDB", L"Enabled", 0, ini.c_str()) != 0;
    g_app.settings.srcET =
        GetPrivateProfileIntW(L"Sources", L"EmergingThreats", 1, ini.c_str()) != 0;
    g_app.settings.srcBlocklist =
        GetPrivateProfileIntW(L"Sources", L"BlocklistDe", 1, ini.c_str()) != 0;
    g_app.settings.srcFeodo =
        GetPrivateProfileIntW(L"Sources", L"FeodoTracker", 1, ini.c_str()) != 0;
    g_app.settings.cacheTtlHours =
        GetPrivateProfileIntW(L"Cache", L"TtlHours", 24, ini.c_str());
}

static void SaveSettings() {
    std::wstring ini = GetIniPath();
    WritePrivateProfileStringW(L"AbuseIPDB", L"ApiKey",
        g_app.settings.abuseApiKey.c_str(), ini.c_str());
    WritePrivateProfileStringW(L"AbuseIPDB", L"Enabled",
        g_app.settings.abuseEnabled ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"Sources", L"EmergingThreats",
        g_app.settings.srcET ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"Sources", L"BlocklistDe",
        g_app.settings.srcBlocklist ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"Sources", L"FeodoTracker",
        g_app.settings.srcFeodo ? L"1" : L"0", ini.c_str());
    wchar_t ttl[16];
    swprintf(ttl, 16, L"%d", g_app.settings.cacheTtlHours);
    WritePrivateProfileStringW(L"Cache", L"TtlHours", ttl, ini.c_str());
}

// ================================================================
//  Export Report
// ================================================================
static void ExportReport() {
    if (g_app.results.empty()) return;

    wchar_t filename[MAX_PATH] = L"netguard_report.txt";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_app.hwndMain;
    ofn.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files\0*.*\0";
    ofn.lpstrFile   = filename;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"txt";

    if (!GetSaveFileNameW(&ofn)) return;

    std::ofstream f(WideToUtf8(filename));
    if (!f.is_open()) {
        MessageBoxW(g_app.hwndMain, L"\x65E0\x6CD5\x521B\x5EFA\x6587\x4EF6",
                    L"NetGuard", MB_OK | MB_ICONERROR);
        return;
    }

    time_t now = time(nullptr);
    char tb[64];
    strftime(tb, sizeof(tb), "%Y-%m-%d %H:%M:%S", localtime(&now));

    f << "========================================\n";
    f << "  NetGuard Scan Report\n";
    f << "  Time: " << tb << "\n";
    f << "  Connections: " << g_app.results.size() << "\n";
    f << "========================================\n\n";

    for (size_t i = 0; i < g_app.results.size(); i++) {
        const auto& c = g_app.results[i];
        f << "[" << RiskNameA(c.risk) << "] #" << (i + 1)
          << " " << c.processName << " (PID:" << c.pid << ")\n";
        f << "  TCP " << c.localAddr << ":" << c.localPort
          << " -> " << c.remoteAddr << ":" << c.remotePort
          << " [" << c.state << "]\n";
        if (!c.processPath.empty())
            f << "  Path: " << c.processPath << "\n";
        for (const auto& r : c.reasons)
            f << "  >> " << r << "\n";
        f << "\n";
    }
    f.close();
    MessageBoxW(g_app.hwndMain,
        L"\x62A5\x544A\x5DF2\x5BFC\x51FA",  // 报告已导出
        L"NetGuard", MB_OK | MB_ICONINFORMATION);
}

// ================================================================
//  ListView Management
// ================================================================
static void InitListView() {
    HWND lv = g_app.hwndListView;
    ListView_SetExtendedListViewStyle(lv,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    struct Col { const wchar_t* name; int width; };
    Col cols[] = {
        {L"#",    40},
        // 风险
        {L"\x98CE\x9669", 55},
        // 进程
        {L"\x8FDB\x7A0B", 130},
        {L"PID",  55},
        // 本地地址
        {L"\x672C\x5730\x5730\x5740", 150},
        // 远程地址
        {L"\x8FDC\x7A0B\x5730\x5740", 150},
        // 状态
        {L"\x72B6\x6001", 95},
        // 风险原因
        {L"\x98CE\x9669\x539F\x56E0", 380},
    };

    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.fmt  = LVCFMT_LEFT;
    for (int i = 0; i < 8; i++) {
        lvc.pszText = const_cast<wchar_t*>(cols[i].name);
        lvc.cx      = cols[i].width;
        SendMessageW(lv, LVM_INSERTCOLUMNW, i, (LPARAM)&lvc);
    }
}

static void LvSetTextW(HWND lv, int item, int sub, const wchar_t* text) {
    LVITEMW lvi = {};
    lvi.iSubItem = sub;
    lvi.pszText  = const_cast<wchar_t*>(text);
    SendMessageW(lv, LVM_SETITEMTEXTW, item, (LPARAM)&lvi);
}

static void PopulateListView() {
    HWND lv = g_app.hwndListView;
    SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv);

    int idx = 0;
    for (size_t i = 0; i < g_app.results.size(); i++) {
        const auto& c = g_app.results[i];

        // Apply filter
        bool show = false;
        switch (g_app.currentFilter) {
            case 0: show = (c.risk >= RISK_LOW); break;
            case 1: show = true; break;
            case 2: show = (c.state == "ESTABLISHED"); break;
            default: show = true; break;
        }
        if (!show) continue;

        // # column
        wchar_t num[16];
        swprintf(num, 16, L"%d", idx + 1);
        LVITEMW lvi = {};
        lvi.mask    = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem   = idx;
        lvi.pszText = num;
        lvi.lParam  = (LPARAM)c.risk;
        SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

        // Risk
        LvSetTextW(lv, idx, 1, RiskNameW(c.risk));

        // Process
        std::wstring proc = Utf8ToWide(c.processName);
        LvSetTextW(lv, idx, 2, proc.c_str());

        // PID
        wchar_t pid[16];
        swprintf(pid, 16, L"%lu", c.pid);
        LvSetTextW(lv, idx, 3, pid);

        // Local address
        std::wstring local = Utf8ToWide(c.localAddr + ":" + std::to_string(c.localPort));
        LvSetTextW(lv, idx, 4, local.c_str());

        // Remote address
        std::wstring remote = Utf8ToWide(c.remoteAddr + ":" + std::to_string(c.remotePort));
        LvSetTextW(lv, idx, 5, remote.c_str());

        // State
        std::wstring state = Utf8ToWide(c.state);
        LvSetTextW(lv, idx, 6, state.c_str());

        // Reasons
        std::string allReasons;
        for (size_t r = 0; r < c.reasons.size(); r++) {
            if (r > 0) allReasons += " | ";
            allReasons += c.reasons[r];
        }
        std::wstring wr = Utf8ToWide(allReasons);
        LvSetTextW(lv, idx, 7, wr.c_str());

        idx++;
    }

    SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(lv, NULL, TRUE);
}

static void UpdateStatusBar() {
    // Part 0: Status
    int total = (int)g_app.results.size();
    int suspicious = 0;
    for (const auto& c : g_app.results)
        if (c.risk >= RISK_LOW) suspicious++;

    wchar_t buf[256];
    if (g_app.scanning)
        swprintf(buf, 256, L" \x6B63\x5728\x626B\x63CF...");  // 正在扫描...
    else if (total > 0)
        swprintf(buf, 256,
            L" \x626B\x63CF\x5B8C\x6210: %d \x6761\x8FDE\x63A5, %d \x53EF\x7591",
            total, suspicious);  // 扫描完成: X 条连接, Y 可疑
    else
        swprintf(buf, 256, L" \x5C31\x7EEA");  // 就绪

    SendMessageW(g_app.hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)buf);

    // Part 1: Blacklist count
    EnterCriticalSection(&g_app.csBlacklist);
    int blCount = (int)g_blacklist.size();
    LeaveCriticalSection(&g_app.csBlacklist);
    swprintf(buf, 256, L" \x9ED1\x540D\x5355: %d", blCount);  // 黑名单: N
    SendMessageW(g_app.hwndStatusBar, SB_SETTEXTW, 1, (LPARAM)buf);

    // Part 2: Admin status
    swprintf(buf, 256, L" Admin: %s", IsAdmin() ? L"\x2713" : L"\x2717");
    SendMessageW(g_app.hwndStatusBar, SB_SETTEXTW, 2, (LPARAM)buf);
}

// ================================================================
//  Settings Dialog (Programmatic)
// ================================================================
static BOOL CALLBACK SetFontProc(HWND hwnd, LPARAM lParam) {
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

// Store settings dialog control handles
struct SettingsControls {
    HWND hEditKey, hChkAbuse, hChkET, hChkBL, hChkFeodo, hComboCache;
};
static SettingsControls s_setCtrl;

LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        int y = 15;
        // Group: AbuseIPDB
        CreateWindowExW(0, L"BUTTON", L"AbuseIPDB API",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            10, y, 370, 80, hwnd, NULL, g_app.hInstance, NULL);
        CreateWindowExW(0, L"STATIC", L"API Key:",
            WS_CHILD | WS_VISIBLE, 25, y+22, 55, 18, hwnd, NULL, g_app.hInstance, NULL);
        s_setCtrl.hEditKey = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            85, y+19, 285, 22, hwnd, (HMENU)(INT_PTR)IDC_EDIT_APIKEY, g_app.hInstance, NULL);
        // 启用 AbuseIPDB 查询
        s_setCtrl.hChkAbuse = CreateWindowExW(0, L"BUTTON",
            L"\x542F\x7528 AbuseIPDB \x67E5\x8BE2",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            25, y+50, 200, 18, hwnd, (HMENU)(INT_PTR)IDC_CHK_ABUSEIPDB, g_app.hInstance, NULL);

        y += 95;
        // Group: Sources
        // 在线黑名单源
        CreateWindowExW(0, L"BUTTON",
            L"\x5728\x7EBF\x9ED1\x540D\x5355\x6E90",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            10, y, 370, 75, hwnd, NULL, g_app.hInstance, NULL);
        s_setCtrl.hChkET = CreateWindowExW(0, L"BUTTON", L"Emerging Threats",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            25, y+20, 160, 18, hwnd, (HMENU)(INT_PTR)IDC_CHK_ET, g_app.hInstance, NULL);
        s_setCtrl.hChkBL = CreateWindowExW(0, L"BUTTON", L"Blocklist.de",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            200, y+20, 160, 18, hwnd, (HMENU)(INT_PTR)IDC_CHK_BLOCKLIST, g_app.hInstance, NULL);
        s_setCtrl.hChkFeodo = CreateWindowExW(0, L"BUTTON", L"Feodo Tracker",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            25, y+45, 160, 18, hwnd, (HMENU)(INT_PTR)IDC_CHK_FEODO, g_app.hInstance, NULL);

        y += 90;
        // Group: Cache
        // 缓存设置
        CreateWindowExW(0, L"BUTTON",
            L"\x7F13\x5B58\x8BBE\x7F6E",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            10, y, 370, 55, hwnd, NULL, g_app.hInstance, NULL);
        // 有效期:
        CreateWindowExW(0, L"STATIC",
            L"\x6709\x6548\x671F:",
            WS_CHILD | WS_VISIBLE, 25, y+25, 50, 18, hwnd, NULL, g_app.hInstance, NULL);
        s_setCtrl.hComboCache = CreateWindowExW(0, L"COMBOBOX", NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            80, y+22, 100, 120, hwnd, (HMENU)(INT_PTR)IDC_COMBO_CACHE, g_app.hInstance, NULL);
        // 清除缓存
        CreateWindowExW(0, L"BUTTON",
            L"\x6E05\x9664\x7F13\x5B58",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            260, y+22, 110, 24, hwnd, (HMENU)(INT_PTR)IDC_BTN_CLEARCACHE, g_app.hInstance, NULL);

        y += 70;
        // 确定/取消
        CreateWindowExW(0, L"BUTTON",
            L"\x786E\x5B9A",  // 确定
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            190, y, 90, 28, hwnd, (HMENU)(INT_PTR)IDOK, g_app.hInstance, NULL);
        // 取消
        CreateWindowExW(0, L"BUTTON",
            L"\x53D6\x6D88",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            290, y, 90, 28, hwnd, (HMENU)(INT_PTR)IDCANCEL, g_app.hInstance, NULL);

        // Set font
        EnumChildWindows(hwnd, SetFontProc, (LPARAM)g_app.hFont);

        // Populate from settings
        SetWindowTextW(s_setCtrl.hEditKey, g_app.settings.abuseApiKey.c_str());
        SendMessageW(s_setCtrl.hChkAbuse, BM_SETCHECK,
            g_app.settings.abuseEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(s_setCtrl.hChkET, BM_SETCHECK,
            g_app.settings.srcET ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(s_setCtrl.hChkBL, BM_SETCHECK,
            g_app.settings.srcBlocklist ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(s_setCtrl.hChkFeodo, BM_SETCHECK,
            g_app.settings.srcFeodo ? BST_CHECKED : BST_UNCHECKED, 0);

        // Cache combo
        // 1小时 / 6小时 / 24小时 / 永不过期
        SendMessageW(s_setCtrl.hComboCache, CB_ADDSTRING, 0, (LPARAM)L"1 \x5C0F\x65F6");
        SendMessageW(s_setCtrl.hComboCache, CB_ADDSTRING, 0, (LPARAM)L"6 \x5C0F\x65F6");
        SendMessageW(s_setCtrl.hComboCache, CB_ADDSTRING, 0, (LPARAM)L"24 \x5C0F\x65F6");
        SendMessageW(s_setCtrl.hComboCache, CB_ADDSTRING, 0,
            (LPARAM)L"\x6C38\x4E0D\x8FC7\x671F");
        int sel = 2;
        if (g_app.settings.cacheTtlHours <= 1) sel = 0;
        else if (g_app.settings.cacheTtlHours <= 6) sel = 1;
        else if (g_app.settings.cacheTtlHours <= 24) sel = 2;
        else sel = 3;
        SendMessageW(s_setCtrl.hComboCache, CB_SETCURSEL, sel, 0);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            wchar_t buf[512];
            GetWindowTextW(s_setCtrl.hEditKey, buf, 512);
            g_app.settings.abuseApiKey = buf;
            g_app.settings.abuseEnabled =
                SendMessageW(s_setCtrl.hChkAbuse, BM_GETCHECK, 0, 0) == BST_CHECKED;
            g_app.settings.srcET =
                SendMessageW(s_setCtrl.hChkET, BM_GETCHECK, 0, 0) == BST_CHECKED;
            g_app.settings.srcBlocklist =
                SendMessageW(s_setCtrl.hChkBL, BM_GETCHECK, 0, 0) == BST_CHECKED;
            g_app.settings.srcFeodo =
                SendMessageW(s_setCtrl.hChkFeodo, BM_GETCHECK, 0, 0) == BST_CHECKED;
            int sel = (int)SendMessageW(s_setCtrl.hComboCache, CB_GETCURSEL, 0, 0);
            int hours[] = {1, 6, 24, 99999};
            g_app.settings.cacheTtlHours = (sel >= 0 && sel < 4) ? hours[sel] : 24;
            SaveSettings();
            DestroyWindow(hwnd);
            return 0;
        }
        case IDCANCEL:
            DestroyWindow(hwnd);
            return 0;
        case IDC_BTN_CLEARCACHE: {
            std::wstring cdir = GetCacheDir();
            WIN32_FIND_DATAW fd;
            HANDLE hf = FindFirstFileW((cdir + L"*").c_str(), &fd);
            if (hf != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                        DeleteFileW((cdir + fd.cFileName).c_str());
                } while (FindNextFileW(hf, &fd));
                FindClose(hf);
            }
            // 缓存已清除
            MessageBoxW(hwnd,
                L"\x7F13\x5B58\x5DF2\x6E05\x9664",
                L"NetGuard", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ShowSettingsDialog() {
    EnableWindow(g_app.hwndMain, FALSE);

    RECT rc;
    GetWindowRect(g_app.hwndMain, &rc);
    int pw = rc.right - rc.left, ph = rc.bottom - rc.top;
    int sw = 400, sh = 400;
    int x = rc.left + (pw - sw) / 2;
    int y = rc.top + (ph - sh) / 2;

    // 设置 - NetGuard
    HWND hwndSet = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"NetGuardSettings",
        L"\x8BBE\x7F6E - NetGuard",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        x, y, sw, sh,
        g_app.hwndMain, NULL, g_app.hInstance, NULL);

    MSG msg;
    while (IsWindow(hwndSet)) {
        BOOL bRet = GetMessageW(&msg, NULL, 0, 0);
        if (bRet <= 0) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    EnableWindow(g_app.hwndMain, TRUE);
    SetForegroundWindow(g_app.hwndMain);
}

// ================================================================
//  Main Window Procedure
// ================================================================
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        int bw = 80, bh = 28, gap = 6, topY = 8;

        // Toolbar buttons
        int x = gap;
        // 扫描
        g_app.hwndBtnScan = CreateWindowExW(0, L"BUTTON",
            L"\x626B\x63CF",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, topY, bw, bh, hwnd, (HMENU)(INT_PTR)IDC_BTN_SCAN, g_app.hInstance, NULL);
        x += bw + gap;

        // 停止
        g_app.hwndBtnStop = CreateWindowExW(0, L"BUTTON",
            L"\x505C\x6B62",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            x, topY, bw, bh, hwnd, (HMENU)(INT_PTR)IDC_BTN_STOP, g_app.hInstance, NULL);
        x += bw + gap;

        // 导出报告
        g_app.hwndBtnExport = CreateWindowExW(0, L"BUTTON",
            L"\x5BFC\x51FA\x62A5\x544A",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            x, topY, 90, bh, hwnd, (HMENU)(INT_PTR)IDC_BTN_EXPORT, g_app.hInstance, NULL);
        x += 90 + gap;

        // 更新黑名单
        g_app.hwndBtnBL = CreateWindowExW(0, L"BUTTON",
            L"\x66F4\x65B0\x9ED1\x540D\x5355",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, topY, 100, bh, hwnd, (HMENU)(INT_PTR)IDC_BTN_BLACKLIST, g_app.hInstance, NULL);
        x += 100 + gap;

        // 设置
        g_app.hwndBtnSet = CreateWindowExW(0, L"BUTTON",
            L"\x8BBE\x7F6E",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x, topY, 60, bh, hwnd, (HMENU)(INT_PTR)IDC_BTN_SETTINGS, g_app.hInstance, NULL);
        x += 60 + gap + 20;

        // Filter combo
        // 仅可疑 / 全部连接 / 仅 ESTABLISHED
        g_app.hwndCombo = CreateWindowExW(0, L"COMBOBOX", NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            x, topY, 140, 120, hwnd, (HMENU)(INT_PTR)IDC_COMBO_FILTER, g_app.hInstance, NULL);
        SendMessageW(g_app.hwndCombo, CB_ADDSTRING, 0,
            (LPARAM)L"\x4EC5\x53EF\x7591\x8FDE\x63A5");
        SendMessageW(g_app.hwndCombo, CB_ADDSTRING, 0,
            (LPARAM)L"\x5168\x90E8\x8FDE\x63A5");
        SendMessageW(g_app.hwndCombo, CB_ADDSTRING, 0,
            (LPARAM)L"\x4EC5 ESTABLISHED");
        SendMessageW(g_app.hwndCombo, CB_SETCURSEL, 0, 0);

        // Progress bar (hidden)
        g_app.hwndProgress = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | PBS_MARQUEE,
            0, 42, 800, 4, hwnd, (HMENU)(INT_PTR)IDC_PROGRESSBAR, g_app.hInstance, NULL);

        // ListView
        g_app.hwndListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
            0, 46, 800, 400, hwnd, (HMENU)(INT_PTR)IDC_LISTVIEW, g_app.hInstance, NULL);
        InitListView();

        // Status bar
        g_app.hwndStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, NULL,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_STATUSBAR, g_app.hInstance, NULL);
        int parts[] = {350, 500, -1};
        SendMessageW(g_app.hwndStatusBar, SB_SETPARTS, 3, (LPARAM)parts);

        // Set font for all toolbar controls
        HWND btns[] = {g_app.hwndBtnScan, g_app.hwndBtnStop, g_app.hwndBtnExport,
                       g_app.hwndBtnBL, g_app.hwndBtnSet, g_app.hwndCombo};
        for (auto b : btns)
            SendMessageW(b, WM_SETFONT, (WPARAM)g_app.hFont, TRUE);

        UpdateStatusBar();
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right, h = rc.bottom;

        SendMessageW(g_app.hwndStatusBar, WM_SIZE, 0, 0);
        RECT rcSB;
        GetWindowRect(g_app.hwndStatusBar, &rcSB);
        int sbH = rcSB.bottom - rcSB.top;

        int toolbarH = 42;
        int progH = 4;

        SetWindowPos(g_app.hwndProgress, NULL, 0, toolbarH, w, progH, SWP_NOZORDER);

        int lvTop = toolbarH + progH;
        int lvH = h - lvTop - sbH;
        if (lvH < 0) lvH = 0;
        SetWindowPos(g_app.hwndListView, NULL, 0, lvTop, w, lvH, SWP_NOZORDER);

        // Update status bar parts proportionally
        int p[] = {w / 3, w * 2 / 3, -1};
        SendMessageW(g_app.hwndStatusBar, SB_SETPARTS, 3, (LPARAM)p);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_SCAN:
            if (!g_app.scanning) {
                g_app.scanning = true;
                g_app.cancelScan = false;
                g_app.results.clear();
                PopulateListView();
                EnableWindow(g_app.hwndBtnScan, FALSE);
                EnableWindow(g_app.hwndBtnStop, TRUE);
                EnableWindow(g_app.hwndBtnExport, FALSE);
                ShowWindow(g_app.hwndProgress, SW_SHOW);
                SendMessageW(g_app.hwndProgress, PBM_SETMARQUEE, TRUE, 30);
                UpdateStatusBar();
                g_app.hScanThread = (HANDLE)_beginthreadex(
                    NULL, 0, ScanThreadProc, (void*)hwnd, 0, NULL);
            }
            return 0;

        case IDC_BTN_STOP:
            g_app.cancelScan = true;
            EnableWindow(g_app.hwndBtnStop, FALSE);
            return 0;

        case IDC_BTN_EXPORT:
            ExportReport();
            return 0;

        case IDC_BTN_BLACKLIST:
            if (!g_app.downloadingBl) {
                g_app.downloadingBl = true;
                ShowWindow(g_app.hwndProgress, SW_SHOW);
                SendMessageW(g_app.hwndProgress, PBM_SETMARQUEE, TRUE, 30);
                // 正在更新黑名单...
                SendMessageW(g_app.hwndStatusBar, SB_SETTEXTW, 0,
                    (LPARAM)L" \x6B63\x5728\x66F4\x65B0\x9ED1\x540D\x5355...");
                g_app.hBlThread = (HANDLE)_beginthreadex(
                    NULL, 0, BlacklistDownloadProc, (void*)hwnd, 0, NULL);
            }
            return 0;

        case IDC_BTN_SETTINGS:
            ShowSettingsDialog();
            return 0;

        case IDC_COMBO_FILTER:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                g_app.currentFilter = (int)SendMessageW(
                    g_app.hwndCombo, CB_GETCURSEL, 0, 0);
                PopulateListView();
            }
            return 0;
        }
        break;

    case WM_NOTIFY: {
        LPNMHDR nmhdr = (LPNMHDR)lParam;
        if (nmhdr->idFrom == IDC_LISTVIEW && nmhdr->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW pcd = (LPNMLVCUSTOMDRAW)lParam;
            switch (pcd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: {
                RiskLevel risk = (RiskLevel)(int)pcd->nmcd.lItemlParam;
                pcd->clrText   = RiskTextColor(risk);
                pcd->clrTextBk = RiskBgColor(risk);
                return CDRF_NEWFONT;
            }
            }
        }
        break;
    }

    case WM_SCAN_COMPLETE: {
        auto* pResults = (std::vector<ConnectionInfo>*)lParam;
        g_app.results = std::move(*pResults);
        delete pResults;

        PopulateListView();
        EnableWindow(g_app.hwndBtnScan, TRUE);
        EnableWindow(g_app.hwndBtnStop, FALSE);
        EnableWindow(g_app.hwndBtnExport, !g_app.results.empty());
        ShowWindow(g_app.hwndProgress, SW_HIDE);
        SendMessageW(g_app.hwndProgress, PBM_SETMARQUEE, FALSE, 0);
        UpdateStatusBar();

        if (g_app.hScanThread) {
            CloseHandle(g_app.hScanThread);
            g_app.hScanThread = NULL;
        }

        // Start AbuseIPDB queries if enabled
        if (g_app.settings.abuseEnabled && !g_app.settings.abuseApiKey.empty()) {
            g_app.hAbuseThread = (HANDLE)_beginthreadex(
                NULL, 0, AbuseQueryProc, (void*)hwnd, 0, NULL);
        }
        return 0;
    }

    case WM_BL_COMPLETE: {
        int count = (int)wParam;
        ShowWindow(g_app.hwndProgress, SW_HIDE);
        SendMessageW(g_app.hwndProgress, PBM_SETMARQUEE, FALSE, 0);
        UpdateStatusBar();

        if (g_app.hBlThread) {
            CloseHandle(g_app.hBlThread);
            g_app.hBlThread = NULL;
        }

        wchar_t msg[128];
        swprintf(msg, 128,
            // 黑名单已更新: N 条记录
            L"\x9ED1\x540D\x5355\x5DF2\x66F4\x65B0: %d \x6761\x8BB0\x5F55",
            count);
        MessageBoxW(hwnd, msg, L"NetGuard", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    case WM_ABUSE_RESULT: {
        // Re-assess all results with new AbuseIPDB data
        for (auto& c : g_app.results)
            AssessRisk(c);
        std::sort(g_app.results.begin(), g_app.results.end(),
            [](const ConnectionInfo& a, const ConnectionInfo& b) {
                return a.risk > b.risk;
            });
        PopulateListView();
        UpdateStatusBar();

        if (g_app.hAbuseThread) {
            CloseHandle(g_app.hAbuseThread);
            g_app.hAbuseThread = NULL;
        }
        return 0;
    }

    case WM_CLOSE: {
        g_app.cancelScan = true;
        HANDLE threads[] = {g_app.hScanThread, g_app.hBlThread, g_app.hAbuseThread};
        for (auto h : threads) {
            if (h) {
                WaitForSingleObject(h, 3000);
                CloseHandle(h);
            }
        }
        g_app.hScanThread = g_app.hBlThread = g_app.hAbuseThread = NULL;
        DestroyWindow(hwnd);
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ================================================================
//  WinMain Entry Point
// ================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    g_app.hInstance = hInstance;

    // Initialize critical sections
    InitializeCriticalSection(&g_app.csBlacklist);
    InitializeCriticalSection(&g_app.csAbuseCache);

    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC  = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    // Create font
    g_app.hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    if (!g_app.hFont)
        g_app.hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    // Load settings & local blacklist
    LoadSettings();
    std::string blPath = WideToUtf8(GetExeDir()) + "blacklist.txt";
    LoadBlacklistFile(blPath);

    // Register main window class
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NetGuardMain";
    wc.hIcon         = LoadIcon(NULL, IDI_SHIELD);
    wc.hIconSm       = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    // Register settings window class
    WNDCLASSEXW wcSet = {};
    wcSet.cbSize        = sizeof(wcSet);
    wcSet.lpfnWndProc   = SettingsWndProc;
    wcSet.hInstance     = hInstance;
    wcSet.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wcSet.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcSet.lpszClassName = L"NetGuardSettings";
    RegisterClassExW(&wcSet);

    // Create main window (centered)
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int ww = 1100, wh = 700;
    // NetGuard v2.0 - 网络后门检测工具
    g_app.hwndMain = CreateWindowExW(0, L"NetGuardMain",
        L"NetGuard v2.0 - \x7F51\x7EDC\x540E\x95E8\x68C0\x6D4B\x5DE5\x5177",
        WS_OVERLAPPEDWINDOW,
        (sw - ww) / 2, (sh - wh) / 2, ww, wh,
        NULL, NULL, hInstance, NULL);

    ShowWindow(g_app.hwndMain, nCmdShow);
    UpdateWindow(g_app.hwndMain);

    // Auto-download blacklists on startup
    g_app.downloadingBl = true;
    g_app.hBlThread = (HANDLE)_beginthreadex(
        NULL, 0, BlacklistDownloadProc, (void*)g_app.hwndMain, 0, NULL);

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup
    if (g_app.hFont) DeleteObject(g_app.hFont);
    WSACleanup();
    DeleteCriticalSection(&g_app.csBlacklist);
    DeleteCriticalSection(&g_app.csAbuseCache);

    return (int)msg.wParam;
}
