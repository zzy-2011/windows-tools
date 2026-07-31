// file_monitor_gui.cpp
// 全盘文件行为监控 (GUI版) - 优化版本
// 编译:
//   windres app.rc -O coff -o app.res
//   g++ -std=c++23 -mwindows file_monitor_gui.cpp app.res -luser32 -lkernel32 -ladvapi32 -lcomctl32 -lshell32 -o file_monitor_gui.exe

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <vector>
#include <string>
#include <chrono>
#include <format>
#include <thread>
#include <atomic>
#include <algorithm>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <functional>
#include <sstream>

// ==================== 常量 ====================
#define ID_BTN_START    2001
#define ID_BTN_STOP     2002
#define ID_BTN_CLEAR    2003
#define ID_EDIT_FILTER  2004
#define ID_CHK_SYSTEM   2005
#define ID_LISTVIEW     2006
#define ID_STATUS       2007
#define ID_TIMER        3001
#define MAX_LIST_ITEMS  20000

// ==================== 事件数据 ====================
struct EventData {
    wchar_t time[32];
    int     action;     // 0=Created, 1=Deleted, 2=Modified, 3=Renamed
    std::wstring path;  // 使用wstring以避免缓冲区溢出问题
    
    EventData() : action(0) {
        time[0] = L'\0';
    }
    
    EventData(const wchar_t* t, int a, const std::wstring& p) 
        : action(a), path(p) {
        wcsncpy_s(time, t, 31);
        time[31] = L'\0';
    }
};

// ==================== 排除路径 ====================
static const wchar_t* g_excludes[] = {
    L"\\Windows\\",
    L"\\$Recycle.Bin\\",
    L"\\System Volume Information\\",
    L"\\pagefile.sys",
    L"\\hiberfil.sys",
    L"\\swapfile.sys",
    L"\\Config\\Msi\\",
    L"\\Microsoft\\Windows\\INet",
    L"\\Microsoft\\Windows\\UsrClass",
    L"\\Microsoft\\Windows\\Notification",
    L"\\ntuser.dat",
    L"\\ntuser.ini",
    L"\\NTUSER.DAT",
    nullptr
};

static bool g_showSystem = false;

static bool ShouldExclude(const std::wstring& path) {
    if (g_showSystem) return false;
    for (int i = 0; g_excludes[i]; i++) {
        if (path.find(g_excludes[i]) != std::wstring::npos)
            return true;
    }
    return false;
}

// ==================== 全局变量 ====================
static HINSTANCE g_hInst = nullptr;
static HWND g_hMainWnd = nullptr;
static HWND g_hList = nullptr;
static HWND g_hStatus = nullptr;
static HWND g_hFilter = nullptr;
static HWND g_hBtnStart = nullptr;
static HWND g_hBtnStop = nullptr;
static HWND g_hBtnClear = nullptr;
static HWND g_hChkSystem = nullptr;
static HFONT g_hFont = nullptr;

static std::atomic<int> g_countTotal{0};
static std::atomic<int> g_countCreated{0};
static std::atomic<int> g_countDeleted{0};
static std::atomic<int> g_countModified{0};
static std::atomic<int> g_countRenamed{0};
static std::atomic<bool> g_monitoring{false};

// 优化的线程安全事件队列
class ThreadSafeQueue {
private:
    mutable std::mutex mtx_;
    std::queue<std::unique_ptr<EventData>> queue_;
    std::condition_variable cv_;

public:
    void push(std::unique_ptr<EventData> item) {
        std::lock_guard<std::mutex> lock(mtx_);
        queue_.push(std::move(item));
        cv_.notify_one();
    }

    bool try_pop(std::unique_ptr<EventData>& item) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (queue_.empty()) {
            return false;
        }
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return queue_.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mtx_);
        while (!queue_.empty()) {
            queue_.pop();
        }
    }
    
    // 非阻塞获取所有元素
    std::vector<std::unique_ptr<EventData>> pop_all() {
        std::lock_guard<std::mutex> lock(mtx_);
        std::vector<std::unique_ptr<EventData>> result;
        result.reserve(queue_.size());
        
        while (!queue_.empty()) {
            result.push_back(std::move(queue_.front()));
            queue_.pop();
        }
        return result;
    }
};

static ThreadSafeQueue g_eventQueue;

// ==================== 获取所有固定驱动器 ====================
static std::vector<std::wstring> GetFixedDrives() {
    std::vector<std::wstring> drives;
    drives.reserve(26); // 最多26个驱动器字母
    
    wchar_t buf[512];
    DWORD len = GetLogicalDriveStringsW(512, buf);
    if (len == 0) return drives;
    
    wchar_t* p = buf;
    while (*p) {
        std::wstring drive(p);
        if (GetDriveTypeW(drive.c_str()) == DRIVE_FIXED) {
            drives.push_back(drive);
        }
        p += drive.size() + 1;
    }
    return drives;
}

// ==================== 不区分大小写子串查找 ====================
static bool ContainsI(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    
    auto it = std::search(haystack.begin(), haystack.end(),
                          needle.begin(), needle.end(),
                          [](wchar_t a, wchar_t b) {
                              return towlower(a) == towlower(b);
                          });
    return it != haystack.end();
}

// ==================== 文件监控器类 ====================
class FileMonitor {
public:
    FileMonitor(const std::vector<std::wstring>& paths,
                DWORD bufferSize = 131072)
        : m_bufferSize(bufferSize)
        , m_stopFlag(false)
    {
        for (const auto& p : paths) {
            HANDLE h = CreateFileW(
                p.c_str(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                nullptr
            );
            if (h != INVALID_HANDLE_VALUE) {
                m_handles.push_back(h);
                m_rootPaths.push_back(p);
            }
        }
    }

    ~FileMonitor() {
        Stop();
        for (auto h : m_handles) {
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
    }

    void Start() {
        if (m_handles.empty()) return;
        m_stopFlag = false;
        m_thread = std::thread(&FileMonitor::Run, this);
    }

    void Stop() {
        m_stopFlag = true;
        if (m_thread.joinable()) m_thread.join();
    }

    size_t GetDriveCount() const { return m_rootPaths.size(); }

private:
    int MapAction(DWORD action) {
        switch (action) {
            case FILE_ACTION_ADDED:            return 0;
            case FILE_ACTION_REMOVED:          return 1;
            case FILE_ACTION_MODIFIED:         return 2;
            case FILE_ACTION_RENAMED_OLD_NAME: return -1;
            case FILE_ACTION_RENAMED_NEW_NAME: return 3;
            default:                           return 4;
        }
    }

    bool ReadDir(size_t idx) {
        if (idx >= m_handles.size() || m_handles[idx] == INVALID_HANDLE_VALUE) return false;
        auto& ov = m_overlaps[idx];
        ov = {};
        ov.hEvent = m_events[idx];
        return ReadDirectoryChangesW(
            m_handles[idx],
            m_buffers[idx].data(),
            (DWORD)m_bufferSize,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_ATTRIBUTES
                | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_CREATION
                | FILE_NOTIFY_CHANGE_SECURITY,
            nullptr, &ov, nullptr
        ) != 0;
    }

    void PostEvent(int action, const std::wstring& fullPath) {
        if (ShouldExclude(fullPath)) return;

        using namespace std::chrono;
        auto now = system_clock::now();
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
        auto timet = system_clock::to_time_t(now);
        struct tm tb {};
        localtime_s(&tb, &timet);
        
        wchar_t timeStr[32];
        wcsftime(timeStr, 32, L"%H:%M:%S", &tb);

        auto data = std::make_unique<EventData>(timeStr, action, fullPath);
        g_eventQueue.push(std::move(data));
    }

    void ProcessBuffer(size_t idx, DWORD bytes) {
        auto* ptr = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(m_buffers[idx].data());
        std::wstring pendingRenameOld;

        while (true) {
            std::wstring name(ptr->FileName, ptr->FileNameLength / sizeof(WCHAR));
            std::wstring fullPath = m_rootPaths[idx];
            if (fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            int action = MapAction(ptr->Action);

            if (action == -1) {
                pendingRenameOld = fullPath;
            } else if (action == 3 && !pendingRenameOld.empty()) {
                PostEvent(3, fullPath);
                pendingRenameOld.clear();
            } else if (action >= 0) {
                PostEvent(action, fullPath);
            }

            if (ptr->NextEntryOffset == 0) break;
            ptr = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                      reinterpret_cast<BYTE*>(ptr) + ptr->NextEntryOffset);
        }
    }

    void Run() {
        size_t n = m_handles.size();
        m_buffers.resize(n, std::vector<unsigned char>(m_bufferSize));
        m_events.resize(n);
        m_overlaps.resize(n);

        for (size_t i = 0; i < n; ++i) {
            m_events[i] = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            ReadDir(i);
        }

        while (!m_stopFlag) {
            DWORD wait = WaitForMultipleObjects(
                (DWORD)n, m_events.data(), FALSE, 500);
            if (wait == WAIT_TIMEOUT) continue;

            if (wait >= WAIT_OBJECT_0 && wait < WAIT_OBJECT_0 + n) {
                size_t idx = wait - WAIT_OBJECT_0;
                DWORD bytes = 0;
                if (GetOverlappedResult(m_handles[idx],
                                        &m_overlaps[idx], &bytes, FALSE) && bytes > 0) {
                    ProcessBuffer(idx, bytes);
                }
                if (!m_stopFlag) {
                    ResetEvent(m_events[idx]);
                    ReadDir(idx);
                }
            }
        }
        for (auto e : m_events) CloseHandle(e);
    }

    std::vector<HANDLE> m_handles;
    std::vector<std::wstring> m_rootPaths;
    std::vector<std::vector<unsigned char>> m_buffers;
    std::vector<HANDLE> m_events;
    std::vector<OVERLAPPED> m_overlaps;
    DWORD m_bufferSize;
    std::atomic<bool> m_stopFlag;
    std::thread m_thread;
};

static FileMonitor* g_monitor = nullptr;

// ==================== 冲刷事件队列到列表 ====================
static void FlushEventQueue() {
    // 获取所有事件
    auto events = g_eventQueue.pop_all();
    if (events.empty()) return;

    // 获取过滤文本
    wchar_t filter[256] = {};
    GetWindowTextW(g_hFilter, filter, 256);
    std::wstring filterStr = filter;

    // 临时禁用重绘以提高性能
    SendMessage(g_hList, WM_SETREDRAW, FALSE, 0);

    for (auto& data : events) {
        // 应用过滤
        if (!filterStr.empty() && !ContainsI(data->path, filterStr)) {
            continue;
        }

        int count = ListView_GetItemCount(g_hList);
        if (count >= MAX_LIST_ITEMS) {
            ListView_DeleteItem(g_hList, 0);
        }

        int idx = ListView_GetItemCount(g_hList);
        static const wchar_t* actionStr[] = {
            L"CREATED", L"DELETED", L"MODIFIED", L"RENAMED", L"UNKNOWN"
        };
        int ai = (data->action >= 0 && data->action <= 3) ? data->action : 4;

        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.pszText = data->time;
        lvi.lParam = (LPARAM)data->action;
        int actualIdx = (int)SendMessage(g_hList, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

        // 设置操作列
        if (actualIdx >= 0) {
            LVITEMW lvi2 = {};
            lvi2.mask = LVIF_TEXT;
            lvi2.iItem = actualIdx;
            lvi2.iSubItem = 1;
            lvi2.pszText = (LPWSTR)actionStr[ai];
            SendMessage(g_hList, LVM_SETITEMTEXTW, actualIdx, (LPARAM)&lvi2);

            // 设置路径列
            LVITEMW lvi3 = {};
            lvi3.mask = LVIF_TEXT;
            lvi3.iItem = actualIdx;
            lvi3.iSubItem = 2;
            lvi3.pszText = (LPWSTR)data->path.c_str();
            SendMessage(g_hList, LVM_SETITEMTEXTW, actualIdx, (LPARAM)&lvi3);
        }

        // 更新计数
        g_countTotal++;
        switch (data->action) {
            case 0: g_countCreated++; break;
            case 1: g_countDeleted++; break;
            case 2: g_countModified++; break;
            case 3: g_countRenamed++; break;
        }
    }

    // 恢复重绘并刷新
    SendMessage(g_hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hList, nullptr, TRUE);

    // 滚动到最新
    int last = ListView_GetItemCount(g_hList) - 1;
    if (last >= 0) ListView_EnsureVisible(g_hList, last, FALSE);
}

// ==================== 更新状态栏 ====================
static void UpdateStatusBar() {
    std::wstring drives;
    if (g_monitoring && g_monitor) {
        auto fixedDrives = GetFixedDrives();
        for (const auto& d : fixedDrives) {
            if (!drives.empty()) drives += L" ";
            drives += d.substr(0, 2);
        }
    }

    std::wstring text = std::format(
        L"事件: {} | 创建: {} | 删除: {} | 修改: {} | 重命名: {} | 队列: {} | {}",
        g_countTotal.load(), g_countCreated.load(), g_countDeleted.load(),
        g_countModified.load(), g_countRenamed.load(),
        g_eventQueue.size(),
        g_monitoring.load() ? (L"监控中: " + drives) : std::wstring(L"未启动")
    );
    SendMessage(g_hStatus, SB_SETTEXT, 0, (LPARAM)text.c_str());

    // 更新窗口标题
    std::wstring title = g_monitoring.load()
        ? L"全盘文件行为监控 [监控中]"
        : L"全盘文件行为监控";
    SetWindowTextW(g_hMainWnd, title.c_str());
}

// ==================== 更新按钮状态 ====================
static void UpdateButtons() {
    EnableWindow(g_hBtnStart, !g_monitoring);
    EnableWindow(g_hBtnStop, g_monitoring.load());
}

// ==================== 创建界面 ====================
static void CreateUI(HWND hWnd) {
    g_hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    // --- 按钮行 ---
    g_hBtnStart = CreateWindowW(L"BUTTON", L"开始监控",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 10, 110, 32, hWnd, (HMENU)ID_BTN_START, g_hInst, nullptr);

    g_hBtnStop = CreateWindowW(L"BUTTON", L"停止监控",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, 10, 110, 32, hWnd, (HMENU)ID_BTN_STOP, g_hInst, nullptr);

    g_hBtnClear = CreateWindowW(L"BUTTON", L"清空列表",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        250, 10, 100, 32, hWnd, (HMENU)ID_BTN_CLEAR, g_hInst, nullptr);

    g_hChkSystem = CreateWindowW(L"BUTTON", L"显示系统事件",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        370, 14, 130, 24, hWnd, (HMENU)ID_CHK_SYSTEM, g_hInst, nullptr);

    // --- 过滤行 ---
    CreateWindowW(L"STATIC", L"过滤:",
        WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        10, 50, 50, 24, hWnd, nullptr, g_hInst, nullptr);

    g_hFilter = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        65, 50, 300, 24, hWnd, (HMENU)ID_EDIT_FILTER, g_hInst, nullptr);

    // --- ListView ---
    g_hList = CreateWindowW(WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL
        | LVS_SHOWSELALWAYS | WS_BORDER | WS_VSCROLL | WS_HSCROLL
        | LVS_EX_FULLROWSELECT,
        10, 84, 760, 400, hWnd, (HMENU)ID_LISTVIEW, g_hInst, nullptr);

    ListView_SetExtendedListViewStyle(g_hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    // 列
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.fmt = LVCFMT_LEFT;

    lvc.pszText = (LPWSTR)L"时间";
    lvc.cx = 90;
    SendMessage(g_hList, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

    lvc.pszText = (LPWSTR)L"操作";
    lvc.cx = 100;
    SendMessage(g_hList, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

    lvc.pszText = (LPWSTR)L"文件路径";
    lvc.cx = 550;
    SendMessage(g_hList, LVM_INSERTCOLUMNW, 2, (LPARAM)&lvc);

    // --- 状态栏 ---
    g_hStatus = CreateWindowW(STATUSCLASSNAMEW, L"就绪",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWnd, (HMENU)ID_STATUS, g_hInst, nullptr);

    // 设置字体
    for (auto h : { g_hBtnStart, g_hBtnStop, g_hBtnClear,
                     g_hChkSystem, g_hFilter, g_hList, g_hStatus }) {
        SendMessage(h, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    }
    // 过滤标签
    EnumChildWindows(hWnd, [](HWND h, LPARAM lp) -> BOOL {
        wchar_t cls[16];
        GetClassNameW(h, cls, 16);
        if (wcscmp(cls, L"Static") == 0) {
            SendMessage(h, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        }
        return TRUE;
    }, 0);

    // 初始状态
    EnableWindow(g_hBtnStop, FALSE);
}

// ==================== 窗口过程 ====================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        CreateUI(hWnd);
        SetTimer(hWnd, ID_TIMER, 200, nullptr);
        UpdateStatusBar();
        return 0;
    }

    case WM_SIZE: {
        int cx = LOWORD(lParam);
        int cy = HIWORD(lParam);
        if (cx < 100 || cy < 100) break;

        // 状态栏自适应
        SendMessage(g_hStatus, WM_SIZE, 0, 0);
        RECT rcS;
        GetWindowRect(g_hStatus, &rcS);
        int statusH = rcS.bottom - rcS.top;

        // ListView 填充剩余区域
        MoveWindow(g_hList, 10, 84, cx - 20, cy - 84 - statusH - 10, TRUE);

        // 过滤框宽度
        MoveWindow(g_hFilter, 65, 50, cx - 80, 24, TRUE);

        // 最后一列自动填充
        ListView_SetColumnWidth(g_hList, 2, LVSCW_AUTOSIZE_USEHEADER);
        return 0;
    }

    case WM_TIMER: {
        if (wParam == ID_TIMER) {
            FlushEventQueue();
            UpdateStatusBar();
        }
        return 0;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_BTN_START: {
            if (g_monitor) {
                g_monitor->Stop();
                delete g_monitor;
                g_monitor = nullptr;
            }
            auto drives = GetFixedDrives();
            if (drives.empty()) {
                MessageBoxW(hWnd, L"未检测到固定驱动器！", L"错误", MB_ICONERROR);
                break;
            }
            g_monitoring = true;
            g_monitor = new FileMonitor(drives);
            g_monitor->Start();
            UpdateButtons();
            UpdateStatusBar();
            break;
        }
        case ID_BTN_STOP: {
            g_monitoring = false;
            if (g_monitor) {
                g_monitor->Stop();
                delete g_monitor;
                g_monitor = nullptr;
            }
            FlushEventQueue(); // 清空剩余事件
            UpdateButtons();
            UpdateStatusBar();
            break;
        }
        case ID_BTN_CLEAR: {
            ListView_DeleteAllItems(g_hList);
            g_countTotal = g_countCreated = g_countDeleted
                = g_countModified = g_countRenamed = 0;
            UpdateStatusBar();
            break;
        }
        case ID_CHK_SYSTEM: {
            g_showSystem = (SendMessage(g_hChkSystem, BM_GETCHECK, 0, 0) == BST_CHECKED);
            break;
        }
        }
        return 0;
    }

    case WM_NOTIFY: {
        auto* nmhdr = (NMHDR*)lParam;
        if (nmhdr->idFrom == ID_LISTVIEW) {
            // --- 颜色编码 ---
            if (nmhdr->code == NM_CUSTOMDRAW) {
                auto* lvcd = (NMLVCUSTOMDRAW*)lParam;
                switch (lvcd->nmcd.dwDrawStage) {
                case CDDS_PREPAINT:
                    return CDRF_NOTIFYITEMDRAW;
                case CDDS_ITEMPREPAINT: {
                    int action = (int)lvcd->nmcd.lItemlParam;
                    switch (action) {
                    case 0: lvcd->clrText = RGB(0, 128, 0);   break; // Created: 绿色
                    case 1: lvcd->clrText = RGB(200, 0, 0);   break; // Deleted: 红色
                    case 2: lvcd->clrText = RGB(0, 0, 180);   break; // Modified: 蓝色
                    case 3: lvcd->clrText = RGB(128, 0, 128);  break; // Renamed: 紫色
                    }
                    return CDRF_NEWFONT;
                }
                }
            }
            // --- 双击打开文件夹 ---
            if (nmhdr->code == NM_DBLCLK) {
                auto* nmitem = (NMITEMACTIVATE*)lParam;
                if (nmitem->iItem >= 0) {
                    wchar_t path[2048] = {};
                    LVITEMW lviGet = {};
                    lviGet.iSubItem = 2;
                    lviGet.pszText = path;
                    lviGet.cchTextMax = 2048;
                    SendMessage(g_hList, LVM_GETITEMTEXTW, nmitem->iItem, (LPARAM)&lviGet);
                    std::wstring dir = path;
                    auto pos = dir.find_last_of(L"\\/");
                    if (pos != std::wstring::npos) {
                        dir = dir.substr(0, pos);
                    }
                    ShellExecuteW(nullptr, L"explore", dir.c_str(),
                                  nullptr, nullptr, SW_SHOWNORMAL);
                }
            }
            // --- 右键菜单 ---
            if (nmhdr->code == NM_RCLICK) {
                auto* nmitem = (NMITEMACTIVATE*)lParam;
                POINT pt = { nmitem->ptAction.x, nmitem->ptAction.y };
                ClientToScreen(g_hList, &pt);
                
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, 1, L"复制路径");
                AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(hMenu, MF_STRING, 2, L"打开所在文件夹");
                
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                                         pt.x, pt.y, 0, hWnd, nullptr);
                DestroyMenu(hMenu);
                
                if (cmd == 1) { // 复制路径
                    if (nmitem->iItem >= 0) {
                        wchar_t path[2048] = {};
                        LVITEMW lviGet = {};
                        lviGet.iSubItem = 2;
                        lviGet.pszText = path;
                        lviGet.cchTextMax = 2048;
                        SendMessage(g_hList, LVM_GETITEMTEXTW, nmitem->iItem, (LPARAM)&lviGet);
                        
                        if (OpenClipboard(hWnd)) {
                            EmptyClipboard();
                            size_t len = wcslen(path) + 1;
                            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len * sizeof(wchar_t));
                            if (hMem) {
                                wcscpy_s((wchar_t*)GlobalLock(hMem), len, path);
                                GlobalUnlock(hMem);
                                SetClipboardData(CF_UNICODETEXT, hMem);
                            }
                            CloseClipboard();
                        }
                    }
                } else if (cmd == 2) { // 打开所在文件夹
                    if (nmitem->iItem >= 0) {
                        wchar_t path[2048] = {};
                        LVITEMW lviGet = {};
                        lviGet.iSubItem = 2;
                        lviGet.pszText = path;
                        lviGet.cchTextMax = 2048;
                        SendMessage(g_hList, LVM_GETITEMTEXTW, nmitem->iItem, (LPARAM)&lviGet);
                        std::wstring dir = path;
                        auto pos = dir.find_last_of(L"\\/");
                        if (pos != std::wstring::npos) {
                            dir = dir.substr(0, pos);
                        }
                        ShellExecuteW(nullptr, L"explore", dir.c_str(),
                                      nullptr, nullptr, SW_SHOWNORMAL);
                    }
                }
            }
        }
        return 0;
    }

    case WM_DESTROY: {
        g_monitoring = false;
        if (g_monitor) {
            g_monitor->Stop();
            delete g_monitor;
            g_monitor = nullptr;
        }
        g_eventQueue.clear(); // 清空事件队列
        if (g_hFont) DeleteObject(g_hFont);
        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// ==================== WinMain ====================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    g_hInst = hInst;

    // 注册公共控件
    INITCOMMONCONTROLSEX icc = {
        sizeof(INITCOMMONCONTROLSEX),
        ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES
    };
    InitCommonControlsEx(&icc);

    // 注册窗口类
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"FileMonitorGUI";
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    // 创建窗口
    int cx = 960, cy = 640;
    int x = (GetSystemMetrics(SM_CXSCREEN) - cx) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - cy) / 2;

    g_hMainWnd = CreateWindowExW(
        0, L"FileMonitorGUI", L"全盘文件行为监控",
        WS_OVERLAPPEDWINDOW,
        x, y, cx, cy,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    // 消息循环
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}