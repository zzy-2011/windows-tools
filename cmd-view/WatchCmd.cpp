// WatchCmd.cpp - 纯 Win32 API CMD 弹窗监听器
// 编译: g++ WatchCmd.cpp -o WatchCmd.exe -static -std=c++17 -ladvapi32 -s
// MSYS2 MinGW: UNICODE is auto-defined, so we use W APIs directly
#define WIN32_LEAN_AND_MEAN
#ifdef UNICODE
#undef UNICODE
#endif
#ifdef _UNICODE
#undef _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <tlhelp32.h>
#include <conio.h>

#pragma comment(lib, "advapi32.lib")

// ── 全局 ──
static int   g_count   = 0;
static FILE *g_logfp   = NULL;
static bool  g_running = true;
static bool  g_admin   = false;

// ── 控制台 ──
static void SetUTF8() {
    SetConsoleOutputCP(65001);
    setlocale(LC_ALL, "");
}

static void CheckAdmin() {
    HANDLE t = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        TOKEN_ELEVATION te; DWORD l = 0;
        if (GetTokenInformation(t, TokenElevation, &te, sizeof(te), &l) && te.TokenIsElevated)
            g_admin = true;
        CloseHandle(t);
    }
}

static void C(int c) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, (WORD)c);
}

static void Banner() {
    C(11);
    printf("\n  ===========================================================\n");
    printf("   CMD Popup Listener  -  Win32 Polling (MinGW)\n");
    printf("  ===========================================================\n");
    C(8);
    printf("   Log    : CmdPopups_Log_<timestamp>.log\n");
    printf("   Option : -d <sec>  to set duration\n");
    printf("   Ctrl+C : Stop\n");
    if (!g_admin) { C(14); printf("   [!] Not Admin - some processes may be inaccessible.\n"); }
    C(7);
    printf("\n  Listening for cmd.exe processes...\n\n");
}

// ── 用途推断 ──
static const char *What(const char *c) {
    if (!c || !c[0]) return "(no command line)";
    static char b[256];
    struct R { const char *k; const char *d; } r[] = {
        {"reg ",              "Registry Operation"},
        {"regedit",           "Registry Editor"},
        {"schtasks",          "Scheduled Task"},
        {"at ",               "AT Task"},
        {"netstat",           "Network Status"},
        {"/c net ",           "Network Command"},
        {"ping ",             "Ping Test"},
        {"tracert",           "Traceroute"},
        {"nslookup",          "DNS Lookup"},
        {"ipconfig",          "IP Config"},
        {"/release",          "DHCP Release"},
        {"/renew",            "DHCP Renew"},
        {"curl",              "HTTP Request"},
        {"wget",              "HTTP Download"},
        {"Invoke-WebRequest", "PowerShell HTTP"},
        {"python",            "Python"},
        {"pip ",              "Python Package"},
        {"node ",             "Node.js"},
        {"npm ",              "NPM"},
        {"git ",              "Git"},
        {"tasklist",          "Process List"},
        {"taskkill",          "Process Kill"},
        {"powershell",        "PowerShell"},
        {"-enc ",             "PowerShell Encoded"},
        {"mshta",             "MSHTA"},
        {"wscript",           "WScript"},
        {"cscript",           "CScript"},
        {"rundll32",          "Rundll32"},
        {"cmd /c start",      "Sub CMD"},
        {"cmd /k",            "Sub CMD"},
        {"del ",              "Delete Files"},
        {"rmdir ",            "Remove Dir"},
        {"whoami",            "User Query"},
        {"hostname",          "Hostname"},
        {"systeminfo",        "System Info"},
        {"diskpart",          "Disk Partition"},
        {"sc ",               "Service Control"},
        {"certutil",          "Cert/Hash"},
        {"ssh ",              "SSH"},
        {"shutdown",          "Shutdown"},
        {"logoff",            "Logoff"},
        {"clip ",             "Clipboard"},
        {"driverquery",       "Driver Query"},
        {"msiexec",           "MSI Install"},
        {"svchost",           "Windows Service"},
    };
    int n = (int)(sizeof(r) / sizeof(r[0]));
    for (int i = 0; i < n; i++)
        if (strstr(c, r[i].k)) return r[i].d;
    sprintf_s(b, sizeof(b), "Unknown: %.80s", c);
    return b;
}

// ── 获取父进程名（宽字符版） ──
static void ParentNameA(DWORD ppid, char *buf, int sz) {
    buf[0] = '\0';
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!h) { strcpy_s(buf, sz, "?"); return; }
    DWORD s = (DWORD)(sz - 1);
    WCHAR wpath[MAX_PATH];
    if (!QueryFullProcessImageNameW(h, 0, wpath, &s)) {
        CloseHandle(h);
        strcpy_s(buf, sz, "?");
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, buf, sz, NULL, NULL);
    // 取文件名部分
    WCHAR *p = wcsrchr(wpath, L'\\');
    if (p) WideCharToMultiByte(CP_UTF8, 0, p + 1, -1, buf, sz, NULL, NULL);
    CloseHandle(h);
}

// ── 获取进程命令行（宽字符版） ──
static void CmdLineA(DWORD pid, char *buf, int sz) {
    buf[0] = '\0';
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return;
    DWORD s = (DWORD)sz;
    if (QueryFullProcessImageNameA(h, 0, buf, &s)) {
        CloseHandle(h);
        return;
    }
    // Fallback: read PEB -> ProcessParameters -> CommandLine (NT API)
    typedef LONG (WINAPI *NtQIP_t)(HANDLE, INT, PVOID, ULONG, PULONG);
    static NtQIP_t NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQIP");
    if (!NtQIP) { CloseHandle(h); return; }

    PVOID peb = 0;
    LONG r = NtQIP(h, 0, &peb, sizeof(peb), NULL);
    if (r < 0 || !peb) { CloseHandle(h); return; }

    PVOID params = 0;
    SIZE_T rd = 0;
    int off = (sizeof(void*) == 8) ? 0x20 : 0x10;
    ReadProcessMemory(h, (PBYTE)peb + off, &params, sizeof(params), &rd);
    if (!params || rd != sizeof(params)) { CloseHandle(h); return; }

    // RTL_USER_PROCESS_PARAMETERS.CommandLine at offset 0x40
    struct { USHORT Length; USHORT MaximumLength; PVOID Buffer; } us = {0};
    ReadProcessMemory(h, (PBYTE)params + 0x40, &us, sizeof(us), &rd);
    if (!us.Buffer || !us.Length || us.Length > 4096) { CloseHandle(h); return; }

    WCHAR wbuf[2048];
    USHORT copy_len = us.Length < 4094 ? us.Length : 4094;
    ReadProcessMemory(h, us.Buffer, wbuf, copy_len, &rd);
    wbuf[copy_len / 2] = 0;
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, sz, NULL, NULL);
    CloseHandle(h);
}

// ── Ctrl+C ──
static BOOL WINAPI OnCtrl(DWORD t) {
    if (t == CTRL_C_EVENT || t == CTRL_CLOSE_EVENT) { g_running = false; return TRUE; }
    return FALSE;
}

// ── 主 ──
int main(int argc, char *argv[]) {
    SetUTF8();
    CheckAdmin();

    int duration = 0;
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], "-d") == 0) duration = atoi(argv[i + 1]);

    // 日志文件
    char log[MAX_PATH];
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf_s(log, "CmdPopups_Log_%04d%02d%02d_%02d%02d%02d.log",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fopen_s(&g_logfp, log, "w, ccs=UTF-8");
    if (g_logfp) {
        fprintf(g_logfp, "CMD Popup Listener\n");
        fprintf(g_logfp, "Start: %04d-%02d-%02d %02d:%02d:%02d\n\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }

    Banner();
    SetConsoleTitleA("[CMD Listener - Running]");
    SetConsoleCtrlHandler(OnCtrl, TRUE);

    // 追踪 PID 去重
#define MAX_TRACK 4096
    struct { DWORD pid; DWORD tick; } seen[MAX_TRACK];
    memset(seen, 0, sizeof(seen));
    int seen_idx = 0;

    DWORD startTick = GetTickCount();
    int poll = 0;

    while (g_running) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) { Sleep(200); continue; }

        // 使用 W 版本（MinGW GCC 15 强制 UNICODE，ANSI 类型不可用）
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
            // 检查是否是 cmd.exe（宽字符比对）
            if (!(pe.szExeFile[0] == L'c' && pe.szExeFile[1] == L'm' && pe.szExeFile[2] == L'd' &&
                  pe.szExeFile[3] == L'.' && pe.szExeFile[4] == L'e' && pe.szExeFile[5] == L'x' &&
                  pe.szExeFile[6] == L'e' && pe.szExeFile[7] == L'\0')) continue;
            // 转小写再比对（保险）
            bool is_cmd = true;
            for (int ci = 0; ci < 8; ci++)
                if (pe.szExeFile[ci] >= L'A' && pe.szExeFile[ci] <= L'Z')
                    { is_cmd = false; break; }
            if (!is_cmd) continue;

            DWORD pid  = pe.th32ProcessID;
            DWORD ppid = pe.th32ParentProcessID;
            DWORD now  = GetTickCount();

            // 防重复：同一 PID 5秒内不重复报告
            bool is_new = true;
            for (int i = 0; i < MAX_TRACK; i++) {
                if (seen[i].pid == pid) {
                    if (now - seen[i].tick < 5000) is_new = false;
                    else seen[i].tick = now;
                    break;
                }
            }
            if (!is_new) continue;

            seen[seen_idx % MAX_TRACK].pid = pid;
            seen[seen_idx % MAX_TRACK].tick = now;
            seen_idx++;

            char cmdline[2048] = {0};
            char parent[256]   = {0};
            CmdLineA(pid, cmdline, sizeof(cmdline));
            ParentNameA(ppid, parent, sizeof(parent));

            SYSTEMTIME lst; GetLocalTime(&lst);
            char ts[32];
            sprintf_s(ts, "%02d:%02d:%02d.%03d",
                lst.wHour, lst.wMinute, lst.wSecond, lst.wMilliseconds);

            g_count++;
            const char *desc = What(cmdline);

            C(2);  printf("[%s]  [#%d] PID=%lu  Parent=%s\n", ts, g_count, pid, parent);
            C(8);  printf("          Cmd  : %s\n", cmdline[0] ? cmdline : "(inaccessible)");
            C(14); printf("          Desc : %s\n", desc);
            C(7);  printf("\n");

            if (g_logfp) {
                fprintf(g_logfp, "[%s]  [#%d] PID=%lu  Parent=%s\n", ts, g_count, pid, parent);
                fprintf(g_logfp, "          Cmd  : %s\n", cmdline[0] ? cmdline : "(inaccessible)");
                fprintf(g_logfp, "          Desc : %s\n\n", desc);
                fflush(g_logfp);
            }
        }
        CloseHandle(snap);

        if (duration > 0 && (GetTickCount() - startTick) / 1000 >= (DWORD)duration) {
            g_running = false; break;
        }

        Sleep(300);
        poll++;
        if (poll % 20 == 0) {
            printf("\r  [%s] Running... captured: %d     ", __TIME__, g_count);
            fflush(stdout);
        }
    }

    if (g_logfp) { fprintf(g_logfp, "\nTotal captured: %d\n", g_count); fclose(g_logfp); }
    SetConsoleTitleA("[CMD Listener - Stopped]");
    C(11);
    printf("\n  Done. Total: %d  |  Log: %s\n", g_count, log);
    printf("  Press any key to exit...");
    _getch();
    return 0;
}
