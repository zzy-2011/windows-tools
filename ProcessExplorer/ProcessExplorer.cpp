// ProcessExplorer.cpp - Windows GUI 进程浏览器
// MinGW:  g++ -O2 -std=c++17 -municode -DUNICODE -D_UNICODE -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE ProcessExplorer.cpp -o ProcessExplorer.exe -lpsapi -liphlpapi -lws2_32 -lcomctl32 -mwindows
// MSVC:   cl /EHsc /O2 /DUNICODE /D_UNICODE /utf-8 ProcessExplorer.cpp /Fe:ProcessExplorer.exe /link psapi.lib iphlpapi.lib ws2_32.lib user32.lib comctl32.lib

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <memory>
#include <mutex>
#include <chrono>
#include <thread>
#include <functional>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define IDM_REFRESH   1002
#define IDM_KILL      1003
#define IDM_EXIT      1004
#define IDM_TAB_PROC  2001
#define IDM_TAB_NET   2002
#define IDM_TAB_FILES 2003
#define IDM_ABOUT     3001
#define IDM_AUTOREF   4001
#define IDM_SEARCH    5001
#define WMU_REFRESH   (WM_USER+1)
// WMU_DATA_READY: 工作线程采集完成后通知主线程渲染 UI
// lp 为 heap-allocated 数据指针（主线程负责 delete）
#define WMU_DATA_READY (WM_USER+2)
#define TIMER_AUTO_REFRESH 1

static HWND  g_hTab=NULL, g_hLV=NULL, g_hSB=NULL;
static HWND  g_hMain=NULL;
static HWND  g_hSearch=NULL; // 搜索框
static HFONT g_hFont=NULL;
static int   g_iTab=0;
static DWORD g_selPid=0;
static bool  g_busy=false, g_admin=false;
static double g_sysCpu=0.0;
static std::map<DWORD,double> g_cpuMap;
static bool  g_autoRef=false;     // 实时自动刷新开关
static UINT  g_autoRefMs=2000;   // 自动刷新间隔（毫秒）
static std::map<std::string,bool> g_groupOpen; // 进程名分组的展开/折叠状态
static std::map<std::string,bool> g_procGroupOpen; // 进程列表同名项的展开/折叠状态
static std::wstring g_searchText=L""; // 搜索文本

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* PFN_NtQSI)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(NTAPI* PFN_NtQO)(HANDLE,ULONG,PVOID,ULONG,PULONG);
static PFN_NtQSI g_pNtQSI=NULL;
static PFN_NtQO  g_pNtQO=NULL;

static bool InitNt(){
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    if(ntdll){
        g_pNtQSI=(PFN_NtQSI)GetProcAddress(ntdll,"NtQuerySystemInformation");
        g_pNtQO=(PFN_NtQO)GetProcAddress(ntdll,"NtQueryObject");
        return g_pNtQSI != nullptr && g_pNtQO != nullptr;
    }
    return false;
}

static BOOL IsAdmin(){
    HANDLE tok;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&tok))return FALSE;
    TOKEN_ELEVATION te; DWORD len;
    BOOL ok=GetTokenInformation(tok,TokenElevation,&te,sizeof(te),&len);
    CloseHandle(tok);
    return ok && te.TokenIsElevated;
}

static void StatusW(LPCWSTR m){ if(g_hSB) SendMessageW(g_hSB,SB_SETTEXTW,0,(LPARAM)m); }

static std::string W2U(LPCWSTR w){
    if(!w) return "";
    int len=WideCharToMultiByte(CP_UTF8,0,w,-1,nullptr,0,nullptr,nullptr);
    if(len==0) return "";
    std::unique_ptr<char[]> buffer(new char[len]);
    WideCharToMultiByte(CP_UTF8,0,w,-1,buffer.get(),len,nullptr,nullptr);
    return std::string(buffer.get());
}

static std::wstring U2W(const std::string& s){
    if(s.empty()) return L"";
    int len=MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,nullptr,0);
    if(len==0) return L"";
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[len]);
    MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,buffer.get(),len);
    return std::wstring(buffer.get());
}

struct Proc{ DWORD pid; std::string name; double mem,cpu; int thd,hnd; std::string path; };
struct Net{ std::string type; DWORD pid; std::string pn,la,ra; int lp,rp; std::string st; };
struct File{ DWORD pid; std::string pn,path; };
static std::vector<File> g_cachedFiles; // 缓存最近一次文件数据，折叠/展开时只重渲染
static std::vector<Proc> g_cachedProcs; // 缓存最近一次进程数据，折叠/展开时只重渲染
static std::vector<std::string> g_grpNames; // 文件分组名列表
static std::vector<std::string> g_procGrpNames; // 进程分组名列表

// 工作线程采集的数据包
struct RefreshData {
    int                  tab=0;
    std::vector<Proc>    procs;
    std::vector<Net>     nets;
    std::vector<File>    files;
};
struct RefreshArg { HWND hwnd; int tab; DWORD selPid; };

struct CPUSamp{
    ULARGE_INTEGER pI{0,0},pK{0,0},pU{0,0};
    std::map<DWORD,ULONGLONG> pt;
    // 返回 100ns 单位的进程 CPU 时间（kernel + user）
    static ULONGLONG ProcTime(DWORD pid){
        HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pid);
        if(!h) return 0;
        FILETIME c,e,k,u; ULONGLONG r=0;
        if(GetProcessTimes(h,&c,&e,&k,&u))
            r=((ULONGLONG)k.dwHighDateTime<<32|k.dwLowDateTime)
             +((ULONGLONG)u.dwHighDateTime<<32|u.dwLowDateTime);
        CloseHandle(h); return r;
    }
    void Sample(){
        FILETIME i,k,u;
        if(!GetSystemTimes(&i,&k,&u)) return;
        ULARGE_INTEGER I=*(ULARGE_INTEGER*)&i,K=*(ULARGE_INTEGER*)&k,U=*(ULARGE_INTEGER*)&u;
        if(pI.QuadPart==0){
            pI=I; pK=K; pU=U;
            HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
            if(snap!=INVALID_HANDLE_VALUE){PROCESSENTRY32W pe={sizeof(pe)};if(Process32FirstW(snap,&pe))do pt[pe.th32ProcessID]=ProcTime(pe.th32ProcessID);while(Process32NextW(snap,&pe));}CloseHandle(snap); return;
        }
        ULONGLONG iD=I.QuadPart-pI.QuadPart;
        ULONGLONG tD=(K.QuadPart-pK.QuadPart)+(U.QuadPart-pU.QuadPart);
        pI=I; pK=K; pU=U;
        // 系统总 CPU：(1 - idle/total) * 100
        if(tD>0) g_sysCpu=(1.0-(double)iD/(double)tD)*100.0;
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if(snap!=INVALID_HANDLE_VALUE){PROCESSENTRY32W pe={sizeof(pe)};if(Process32FirstW(snap,&pe)){do{
            ULONGLONG t=ProcTime(pe.th32ProcessID);
            ULONGLONG pv=pt[pe.th32ProcessID];
            // 进程 CPU = 该进程占用的 100ns 计数 / 系统总时间片 * 100
            g_cpuMap[pe.th32ProcessID]=(t>pv && tD>0)?(double)(t-pv)/(double)tD*100.0:0.0;
            pt[pe.th32ProcessID]=t;
        }while(Process32NextW(snap,&pe));}CloseHandle(snap);}
    }
} g_cpu;

static double Mem(DWORD p){
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p);
    if(!h) return 0;
    PROCESS_MEMORY_COUNTERS pmc={0};
    pmc.cb=sizeof(pmc);
    BOOL ok=GetProcessMemoryInfo(h,&pmc,sizeof(pmc));
    CloseHandle(h);
    return ok ? pmc.WorkingSetSize/(1024.0*1024.0) : 0.0;
}

static int Hnd(DWORD p){
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p);
    if(!h) return -1;
    DWORD c=0;
    BOOL ok=GetProcessHandleCount(h,&c);
    CloseHandle(h);
    return ok ? (int)c : -1;
}

static int Thd(DWORD p){
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snap==INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te={sizeof(te)};
    int c=0;
    if(Thread32First(snap,&te)) {
        do {
            if(te.th32OwnerProcessID==p) ++c;
        } while(Thread32Next(snap,&te));
    }
    CloseHandle(snap);
    return c;
}

static std::string Path(DWORD p){
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p);
    if(!h) return "";
    WCHAR buf[MAX_PATH];
    DWORD sz=MAX_PATH;
    BOOL ok=QueryFullProcessImageNameW(h,0,buf,&sz);
    CloseHandle(h);
    return ok ? W2U(buf) : "";
}

static std::map<DWORD,std::string> Names(){
    std::map<DWORD,std::string> m;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap!=INVALID_HANDLE_VALUE){
        PROCESSENTRY32W pe={sizeof(pe)};
        if(Process32FirstW(snap,&pe)) {
            do {
                m[pe.th32ProcessID]=W2U(pe.szExeFile);
            } while(Process32NextW(snap,&pe));
        }
        CloseHandle(snap);
    }
    return m;
}

static std::string DumpIPv4(DWORD a){char b[24];sprintf(b,"%u.%u.%u.%u",(unsigned)(a&0xFF),(unsigned)((a>>8)&0xFF),(unsigned)((a>>16)&0xFF),(unsigned)((a>>24)&0xFF));return std::string(b);}

static std::vector<Proc> CollProcs(){
    std::vector<Proc> v;
    // 一次快照获取所有进程+线程，避免对每个进程单独快照
    HANDLE snapP=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapP==INVALID_HANDLE_VALUE) return v;
    
    // 建立 pid->threadCount 映射
    std::map<DWORD,int> thdMap;
    HANDLE snapT=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snapT!=INVALID_HANDLE_VALUE){
        THREADENTRY32 te={sizeof(te)};
        if(Thread32First(snapT,&te)) {
            do {
                thdMap[te.th32OwnerProcessID]++;
            } while(Thread32Next(snapT,&te));
        }
        CloseHandle(snapT);
    }
    
    PROCESSENTRY32W pe={sizeof(pe)};
    if(Process32FirstW(snapP,&pe)){
        do{
            Proc e; e.pid=pe.th32ProcessID; e.name=W2U(pe.szExeFile);
            e.mem=Mem(e.pid); e.cpu=g_cpuMap.count(e.pid)?g_cpuMap[e.pid]:0.0;
            e.thd=thdMap.count(e.pid)?thdMap[e.pid]:0;
            e.hnd=Hnd(e.pid); e.path=Path(e.pid);
            v.push_back(e);
        }while(Process32NextW(snapP,&pe));
    }
    CloseHandle(snapP); return v;
}

static std::vector<Net> CollNet(){
    std::vector<Net> v; auto nm=Names();
    const char* ss[]={"CLOSED","LISTEN","SYN_RCVD","SYN_SENT","ESTABLISHED","FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT","CLOSING","LAST_ACK","TIME_WAIT"};

    // IPv4 TCP
    { std::unique_ptr<MIB_TCPTABLE_OWNER_MODULE,void(*)(void*)> t(nullptr, free);
      ULONG sz=0;
      if(GetExtendedTcpTable(nullptr,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_MODULE_ALL,0)==ERROR_INSUFFICIENT_BUFFER){
          MIB_TCPTABLE_OWNER_MODULE* table = (MIB_TCPTABLE_OWNER_MODULE*)malloc(sz);
          if(table && GetExtendedTcpTable(table,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_MODULE_ALL,0)==NO_ERROR){
              t.reset(table);
              for(DWORD i=0;i<table->dwNumEntries;i++){
                  auto&r=table->table[i]; Net e;
                  e.type="TCP"; e.pid=r.dwOwningPid;
                  e.pn=nm.count(e.pid)?nm[e.pid]:"";
                  e.la=DumpIPv4(r.dwLocalAddr); e.lp=ntohs((u_short)r.dwLocalPort);
                  e.ra=DumpIPv4(r.dwRemoteAddr); e.rp=ntohs((u_short)r.dwRemotePort);
                  e.st=(r.dwState>=0&&r.dwState<=10)?ss[r.dwState]:"?";
                  v.push_back(e);
              }
          }
      }
    }
    // IPv4 UDP
    { std::unique_ptr<MIB_UDPTABLE_OWNER_MODULE,void(*)(void*)> u(nullptr, free);
      ULONG sz=0;
      if(GetExtendedUdpTable(nullptr,&sz,FALSE,AF_INET,UDP_TABLE_OWNER_MODULE,0)==ERROR_INSUFFICIENT_BUFFER){
          MIB_UDPTABLE_OWNER_MODULE* table = (MIB_UDPTABLE_OWNER_MODULE*)malloc(sz);
          if(table && GetExtendedUdpTable(table,&sz,FALSE,AF_INET,UDP_TABLE_OWNER_MODULE,0)==NO_ERROR){
              u.reset(table);
              for(DWORD i=0;i<table->dwNumEntries;i++){
                  auto&r=table->table[i]; Net e;
                  e.type="UDP"; e.pid=r.dwOwningPid;
                  e.pn=nm.count(e.pid)?nm[e.pid]:"";
                  e.la=DumpIPv4(r.dwLocalAddr); e.lp=ntohs((u_short)r.dwLocalPort);
                  e.ra="*"; e.rp=0; e.st="*";
                  v.push_back(e);
              }
          }
      }
    }
    // IPv6 TCP
    { std::unique_ptr<MIB_TCP6TABLE_OWNER_MODULE,void(*)(void*)> t(nullptr, free);
      ULONG sz=0;
      if(GetExtendedTcpTable(nullptr,&sz,FALSE,AF_INET6,TCP_TABLE_OWNER_MODULE_ALL,0)==ERROR_INSUFFICIENT_BUFFER){
          MIB_TCP6TABLE_OWNER_MODULE* table = (MIB_TCP6TABLE_OWNER_MODULE*)malloc(sz);
          if(table && GetExtendedTcpTable(table,&sz,FALSE,AF_INET6,TCP_TABLE_OWNER_MODULE_ALL,0)==NO_ERROR){
              t.reset(table);
              char ab[128];
              for(DWORD i=0;i<table->dwNumEntries;i++){
                  auto&r=table->table[i]; Net e;
                  e.type="TCP6"; e.pid=r.dwOwningPid;
                  e.pn=nm.count(e.pid)?nm[e.pid]:"";
                  sprintf(ab,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      r.ucLocalAddr[0],r.ucLocalAddr[1],r.ucLocalAddr[2],r.ucLocalAddr[3],
                      r.ucLocalAddr[4],r.ucLocalAddr[5],r.ucLocalAddr[6],r.ucLocalAddr[7],
                      r.ucLocalAddr[8],r.ucLocalAddr[9],r.ucLocalAddr[10],r.ucLocalAddr[11],
                      r.ucLocalAddr[12],r.ucLocalAddr[13],r.ucLocalAddr[14],r.ucLocalAddr[15]);
                  e.la=ab; e.lp=ntohs((u_short)r.dwLocalPort); e.ra="*"; e.rp=0; e.st="?";
                  v.push_back(e);
              }
          }
      }
    }
    return v;
}

// 已复制句柄的超时名称查询参数（堆分配防止栈失效）
struct NtQONameArg {
    HANDLE  h;
    wchar_t outName[1024];  // 直接内嵌 buf，不需指针
    ULONG   outLen;
    LONG    status;
    volatile bool done;
};
static DWORD WINAPI NtQONameThread(LPVOID p){
    NtQONameArg* a=(NtQONameArg*)p;
    // ObjectNameInformation = 1
    // NtQueryObject 返回 OBJECT_NAME_INFORMATION { UNICODE_STRING Name; }
    // UNICODE_STRING { USHORT Length; USHORT MaximumLength; PVOID Buffer; }
    // Buffer 指针指向同一缓冲区内的字符串数据
    BYTE raw[4096]={0};
    ULONG nl=0;
    a->status = g_pNtQO(a->h, 1, raw, sizeof(raw), &nl);
    a->outName[0]=0;
    a->outLen=0;
    if(a->status>=0 && nl>0){
        // UNICODE_STRING 在 x64: Length(2) + MaximumLength(2) + padding(4) + Buffer(8) = 16 bytes
        // 在 x86: Length(2) + MaximumLength(2) + Buffer(4) = 8 bytes
#ifdef _WIN64
        USHORT uLen = *(USHORT*)(raw);
        PVOID  uBuf = *(PVOID*)(raw+8);
#else
        USHORT uLen = *(USHORT*)(raw);
        PVOID  uBuf = *(PVOID*)(raw+4);
#endif
        if(uLen>0 && uBuf && uLen<2048){
            // Buffer 指向 raw 内的偏移，需要验证在范围内
            BYTE* start = (BYTE*)uBuf;
            BYTE* base  = raw;
            if(start>=base && start+uLen<=raw+sizeof(raw)){
                ULONG chars=uLen/sizeof(wchar_t);
                if(chars<1023){
                    memcpy(a->outName, start, uLen);
                    a->outName[chars]=0;
                    a->outLen=chars;
                }
            }
        }
    }
    a->done=true;
    return 0;
}

// 查询文件句柄的名称，最多等 timeoutMs 毫秒
static bool QueryFileName(HANDLE dup, std::wstring& outPath, DWORD timeoutMs=300){
    NtQONameArg* a=new NtQONameArg{};
    a->h=dup; a->done=false;
    HANDLE ht=CreateThread(NULL,0,NtQONameThread,a,0,NULL);
    if(!ht){ delete a; return false; }
    DWORD w=WaitForSingleObject(ht,timeoutMs);
    bool ok=false;
    if(w==WAIT_OBJECT_0 && a->status>=0 && a->outLen>0){
        outPath=std::wstring(a->outName, a->outLen);
        ok=!outPath.empty();
    }
    if(w!=WAIT_OBJECT_0){
        // 超时：再等 200ms 让线程自然结束，避免 delete 时线程还在访问 a
        WaitForSingleObject(ht, 200);
    }
    CloseHandle(ht);
    delete a;
    return ok;
}

// 对已复制句柄查询类型（不会阻塞）——注意直接调用不用超时线程
static bool GetHandleTypeName(HANDLE h, std::wstring& typeName){
    // ObjectTypeInformation (class=2) 不会阻塞
    BYTE tb[512]={0}; ULONG tl=0;
    if(g_pNtQO(h,2,tb,sizeof(tb),&tl)<0) return false;
    // UNICODE_STRING: Length(2) + MaximumLength(2) + [padding on x64] + Buffer(ptr)
#ifdef _WIN64
    USHORT uLen = *(USHORT*)(tb);
    PVOID  uBuf = *(PVOID*)(tb+8);
#else
    USHORT uLen = *(USHORT*)(tb);
    PVOID  uBuf = *(PVOID*)(tb+4);
#endif
    if(uLen==0 || uLen>400 || !uBuf) return false;
    // Buffer 指向 tb 内的数据
    BYTE* start=(BYTE*)uBuf;
    if(start>=tb && start+uLen<=tb+sizeof(tb)){
        typeName=std::wstring((wchar_t*)start, uLen/sizeof(wchar_t));
        return !typeName.empty();
    }
    return false;
}

static std::vector<File> CollFiles(DWORD fp){
    std::vector<File> v; auto nm=Names();
    if(!g_pNtQSI || !g_pNtQO) return v;

    // 使用 SystemExtendedHandleInformation (class 64)
    // 返回 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 结构，字段对 x64 友好
    // x64 header: ULONG_PTR NumberOfHandles (8) + ULONG_PTR Reserved (8) = 16 bytes
    // x64 entry (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX):
    //   PVOID     Object;            offset 0,  size 8
    //   ULONG_PTR UniqueProcessId;   offset 8,  size 8
    //   ULONG_PTR HandleValue;       offset 16, size 8
    //   ULONG     GrantedAccess;     offset 24, size 4
    //   USHORT    CreatorBackTraceIndex; offset 28, size 2
    //   USHORT    ObjectTypeIndex;   offset 30, size 2
    //   ULONG     HandleAttributes;  offset 32, size 4
    //   ULONG     Reserved;          offset 36, size 4
    //   Total: 40 bytes per entry
#ifdef _WIN64
    const int ENTRY_SIZE = 40;
    const int HEADER_SIZE = 16;  // two ULONG_PTR
#else
    const int ENTRY_SIZE = 20;   // 32-bit: 4+4+4+4+2+2 = 20
    const int HEADER_SIZE = 8;   // two ULONG
#endif

    ULONG need=131072; 
    std::vector<BYTE> buf;
    NTSTATUS st;
    do{
        buf.resize(need); 
        st=g_pNtQSI(64,buf.data(),(ULONG)buf.size(),&need); 
        need*=2;
    } while(st==0xC0000004L); 
    
    if(st!=0) return v;
#ifdef _WIN64
    ULONG_PTR cnt=*(ULONG_PTR*)buf.data();
#else
    ULONG cnt=*(ULONG*)buf.data();
#endif
    BYTE* p=buf.data()+HEADER_SIZE;
    DWORD curPid=GetCurrentProcessId();
    DWORD lastPid=0; 
    HANDLE lastSrc=nullptr;
    
    for(ULONG_PTR i=0;i<cnt && v.size()<5000;i++){
        BYTE* e=p+i*(ULONG_PTR)ENTRY_SIZE;
#ifdef _WIN64
        DWORD   pid= (DWORD)*(ULONG_PTR*)(e+8);   // UniqueProcessId
        ULONG_PTR hv= *(ULONG_PTR*)(e+16);         // HandleValue (8 bytes on x64)
#else
        DWORD   pid= *(DWORD*)(e+4);
        ULONG   hv = *(ULONG*)(e+8);
#endif
        if(pid==curPid) continue;
        if(fp!=0 && pid!=fp) continue;
        
        // 对同一进程的句柄复用 src
        if(pid!=lastPid){
            if(lastSrc){ CloseHandle(lastSrc); lastSrc=nullptr; }
            lastSrc=OpenProcess(PROCESS_DUP_HANDLE,FALSE,pid);
            lastPid=pid;
        }
        if(!lastSrc) continue;
        
        HANDLE dup=nullptr;
        if(DuplicateHandle(lastSrc,(HANDLE)(ULONG_PTR)hv,
                            GetCurrentProcess(),&dup,0,FALSE,DUPLICATE_SAME_ACCESS) && dup){
            // 先判断类型（不阻塞）
            std::wstring typeName;
            bool isFile=GetHandleTypeName(dup,typeName) && typeName==L"File";
            if(isFile){
                // 再查路径（带超时）
                std::wstring ws;
                if(QueryFileName(dup, ws, 200) && !ws.empty()){
                    bool keep=(ws.find(L'\\')!=std::wstring::npos);
                    if(keep){
                        File fe; fe.pid=pid;
                        fe.pn=nm.count(pid)?nm[pid]:"";
                        fe.path=W2U(ws.c_str());
                        v.push_back(fe);
                    }
                }
            }
            CloseHandle(dup);
        }
    }
    if(lastSrc) CloseHandle(lastSrc);
    
    std::sort(v.begin(),v.end(),[](const File&a,const File&b){
        if(a.pid!=b.pid) return a.pid<b.pid;
        return a.path<b.path;
    });
    
    return v;
}

static void AutoSz(HWND h){int n=Header_GetItemCount(ListView_GetHeader(h));for(int i=0;i<n;i++)ListView_SetColumnWidth(h,i,LVSCW_AUTOSIZE_USEHEADER);}
static void Reset(HWND h){ ListView_DeleteAllItems(h); }

// FIX-B1: 辅助宏：先存储 wstring 再设置，避免悬空指针
// 用法: LV_SETW(lvi, U2W(str))
#define LV_SETW(lvi, wstr_expr) do { std::wstring _tmp=(wstr_expr); (lvi).pszText=(LPWSTR)_tmp.c_str(); SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&(lvi)); } while(0)
#define LV_INSW(lvi, wstr_expr) do { std::wstring _tmp=(wstr_expr); (lvi).pszText=(LPWSTR)_tmp.c_str(); SendMessage(g_hLV,LVM_INSERTITEMW,0,(LPARAM)&(lvi)); } while(0)


// 带搜索过滤的填充函数
static void FillProcsFiltered(const std::vector<Proc>& v){
    int topIdx = ListView_GetTopIndex(g_hLV); // 记录滚动位置
    SendMessage(g_hLV, WM_SETREDRAW, FALSE, 0);
    Reset(g_hLV);
    
    // 仅在列数不对时重新创建列
    if (Header_GetItemCount(ListView_GetHeader(g_hLV)) != 7) {
        while(ListView_DeleteColumn(g_hLV, 0)) {}
        LPCWSTR hdr[]={L"PID",L"\u540D\u79F0",L"\u5185\u5B58(MB)",L"CPU(%)",L"\u72B6\u6001",L"\u53E5\u67C4",L"\u8DEF\u5F84"};
        int w[]={60,150,80,65,50,50,360};
        for(int i=0;i<7;i++){LVCOLUMNW c={};c.mask=LVCF_FMT|LVCF_TEXT|LVCF_WIDTH;c.fmt=(i>=2&&i<=5)?LVCFMT_RIGHT:LVCFMT_LEFT;c.pszText=(LPWSTR)hdr[i];c.cx=w[i];SendMessage(g_hLV,LVM_INSERTCOLUMNW,i,(LPARAM)&c);}
    }
    
    struct Grp { std::string name; std::vector<Proc> items; double totalMem=0, totalCpu=0; int totalThd=0, totalHnd=0; };
    std::vector<Grp> groups;
    std::map<std::string,int> nameIdx;
    
    for(const auto& p : v){
        if (!g_searchText.empty()) {
            std::wstring name = U2W(p.name);
            std::wstring path = U2W(p.path);
            std::wstring pidStr = std::to_wstring(p.pid);
            if (name.find(g_searchText) == std::wstring::npos &&
                path.find(g_searchText) == std::wstring::npos &&
                pidStr.find(g_searchText) == std::wstring::npos) continue;
        }
        
        auto it = nameIdx.find(p.name);
        if(it == nameIdx.end()){
            nameIdx[p.name] = (int)groups.size();
            groups.push_back({p.name, {p}, p.mem, p.cpu, p.thd, p.hnd});
        } else {
            auto& g = groups[it->second];
            g.items.push_back(p);
            g.totalMem += p.mem;
            g.totalCpu += p.cpu;
            g.totalThd += p.thd;
            if(p.hnd > 0) g.totalHnd += p.hnd;
        }
    }
    
    // 排序逻辑：多进程组放在前面，单进程放在后面；组内按名称首字母排序
    std::sort(groups.begin(), groups.end(), [](const Grp& a, const Grp& b) {
        bool aMulti = a.items.size() > 1;
        bool bMulti = b.items.size() > 1;
        if (aMulti != bMulti) return aMulti; // 多进程组优先
        return a.name < b.name; // 同类按名称首字母排序
    });

    g_procGrpNames.clear();
    for(size_t gi=0; gi<groups.size(); gi++) g_procGrpNames.push_back(groups[gi].name);
    
    wchar_t b[128];
    for(size_t gi=0; gi<groups.size(); gi++){
        const auto& g = groups[gi];
        bool isOpen = g_procGroupOpen.count(g.name)?g_procGroupOpen[g.name]:false;
        bool multi = (g.items.size() > 1);
        
        // 1. 插入行（如果是多进程则为父行，否则为单进程行）
        LVITEMW lvi={}; 
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = 0x7FFFFFFF;
        lvi.iSubItem = 0;
        
        // PID列：多进程显示状态图标，单进程显示PID
        std::wstring pid_text = multi ? (isOpen ? L"[-] " : L"[+] ") : std::to_wstring(g.items[0].pid);
        lvi.pszText = (LPWSTR)pid_text.c_str();
        lvi.lParam = (LPARAM)(gi+1); 
        int row = (int)SendMessage(g_hLV, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
        if(row < 0) continue;
        
        // 名称列：名称 + (数量)
        std::wstring name_text = U2W(g.name);
        if(multi) name_text += L" (" + std::to_wstring(g.items.size()) + L")";
        ListView_SetItemText(g_hLV, row, 1, (LPWSTR)name_text.c_str());
        
        // 汇总数据
        swprintf(b, 128, L"%.1f", g.totalMem); ListView_SetItemText(g_hLV, row, 2, b);
        swprintf(b, 128, L"%.1f", g.totalCpu); ListView_SetItemText(g_hLV, row, 3, b);
        _itow(g.totalThd, b, 10); ListView_SetItemText(g_hLV, row, 4, b);
        _itow(g.totalHnd, b, 10); ListView_SetItemText(g_hLV, row, 5, b);
        
        if(!multi){
            // 单进程显示路径
            ListView_SetItemText(g_hLV, row, 6, (LPWSTR)U2W(g.items[0].path).c_str());
        } else {
            // 多进程父行路径列留空或提示
            ListView_SetItemText(g_hLV, row, 6, (LPWSTR)L"<\u591A\u8FDB\u7A0B\u6C47\u603B>");
            
            if(isOpen){
                // 插入子进程行
                for(const auto& p : g.items){
                    LVITEMW sub={}; 
                    sub.mask = LVIF_TEXT | LVIF_PARAM;
                    sub.iItem = ++row; // 紧随父行插入
                    sub.iSubItem = 0;
                    std::wstring sub_pid = L"    " + std::to_wstring(p.pid);
                    sub.pszText = (LPWSTR)sub_pid.c_str();
                    sub.lParam = 0; // 子项
                    int sr = (int)SendMessage(g_hLV, LVM_INSERTITEMW, 0, (LPARAM)&sub);
                    if(sr >= 0){
                        // 子行精简：名称列留空或用虚线表示从属，突出路径
                        ListView_SetItemText(g_hLV, sr, 1, (LPWSTR)L" |--"); 
                        swprintf(b, 128, L"%.1f", p.mem); ListView_SetItemText(g_hLV, sr, 2, b);
                        swprintf(b, 128, L"%.1f", p.cpu); ListView_SetItemText(g_hLV, sr, 3, b);
                        _itow(p.thd, b, 10); ListView_SetItemText(g_hLV, sr, 4, b);
                        _itow(p.hnd, b, 10); ListView_SetItemText(g_hLV, sr, 5, b);
                        std::string dp = p.path.size() > 60 ? p.path.substr(0,57) + "..." : p.path;
                        ListView_SetItemText(g_hLV, sr, 6, (LPWSTR)U2W(dp).c_str());
                    }
                }
            }
        }
    }
    swprintf(b,128,L"  进程: %u  |  分组: %u  |  系统 CPU: %.1f%%", (unsigned)v.size(), (unsigned)groups.size(), g_sysCpu);
    StatusW(b);
    
    // 恢复滚动位置
    if (topIdx > 0) {
        int count = ListView_GetItemCount(g_hLV);
        if (topIdx >= count) topIdx = count - 1;
        // 先滚动到顶部，再滚动到目标位置
        ListView_EnsureVisible(g_hLV, 0, FALSE);
        RECT rcItem = {0};
        if (ListView_GetItemRect(g_hLV, 0, &rcItem, LVIR_BOUNDS)) {
            int itemHeight = rcItem.bottom - rcItem.top;
            SendMessage(g_hLV, LVM_SCROLL, 0, topIdx * itemHeight);
        }
    }

    SendMessage(g_hLV, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hLV, NULL, FALSE); // FALSE: 开启双缓冲时不擦除背景
}

static void FillFilesFiltered(const std::vector<File>& v){
    int topIdx = ListView_GetTopIndex(g_hLV);
    SendMessage(g_hLV, WM_SETREDRAW, FALSE, 0);
    Reset(g_hLV);
    if (Header_GetItemCount(ListView_GetHeader(g_hLV)) != 3) {
        while(ListView_DeleteColumn(g_hLV, 0)) {}
        LPCWSTR hdr[]={L"PID",L"\u8FDB\u7A0B\u540D",L"\u6253\u5F00\u7684\u6587\u4EF6/\u53E5\u67C4"};
        int w[]={60,140,700};
        for(int i=0;i<3;i++){LVCOLUMNW c={};c.mask=LVCF_TEXT|LVCF_WIDTH;c.pszText=(LPWSTR)hdr[i];c.cx=w[i];SendMessage(g_hLV,LVM_INSERTCOLUMNW,i,(LPARAM)&c);}
    }
    wchar_t b[128];
    // 按进程名分组
    struct Grp { std::string name; std::vector<File> items; };
    std::vector<Grp> groups;
    std::map<std::string,int> nameIdx;
    for(size_t i=0;i<v.size();i++){
        if (!g_searchText.empty()) {
            std::wstring pn = U2W(v[i].pn);
            std::wstring path = U2W(v[i].path);
            std::wstring pidStr = std::to_wstring(v[i].pid);
            if (pn.find(g_searchText) == std::wstring::npos &&
                path.find(g_searchText) == std::wstring::npos &&
                pidStr.find(g_searchText) == std::wstring::npos) continue;
        }
        const std::string& pn=v[i].pn;
        auto it=nameIdx.find(pn);
        if(it==nameIdx.end()){
            nameIdx[pn]=(int)groups.size();
            groups.push_back({pn,{v[i]}});
        } else {
            groups[it->second].items.push_back(v[i]);
        }
    }
    // 排序逻辑：多项的分组在前，单项的在后；同类按名称排序
    std::sort(groups.begin(), groups.end(), [](const Grp& a, const Grp& b) {
        bool aMulti = a.items.size() > 1;
        bool bMulti = b.items.size() > 1;
        if (aMulti != bMulti) return aMulti;
        return a.name < b.name;
    });

    // 保存分组名列表，供双击时用 lParam 查找
    g_grpNames.clear();
    for(size_t gi=0;gi<groups.size();gi++) g_grpNames.push_back(groups[gi].name);

    // 插入分组头 + 子行
    for(size_t gi=0;gi<groups.size();gi++){
        const Grp& g=groups[gi];
        bool isOpen=g_groupOpen.count(g.name)?g_groupOpen[g.name]:false;
        bool multi=(g.items.size()>1);
        
        // 1. 插入行
        LVITEMW lvi={}; 
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = 0x7FFFFFFF;
        lvi.iSubItem = 0;
        
        // PID列：多项显示状态图标，单项显示PID
        std::wstring pid_text = multi ? (isOpen ? L"[-] " : L"[+] ") : std::to_wstring(g.items[0].pid);
        lvi.pszText = (LPWSTR)pid_text.c_str();
        lvi.lParam = (LPARAM)(gi+1); 
        int row = (int)SendMessage(g_hLV, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
        if(row < 0) continue;
        
        // 进程名列：名称 + (数量)
        std::wstring name_text = U2W(g.name);
        if(multi) name_text += L" (" + std::to_wstring(g.items.size()) + L")";
        ListView_SetItemText(g_hLV, row, 1, (LPWSTR)name_text.c_str());
        
        if(!multi){
            // 单条目：直接显示路径
            ListView_SetItemText(g_hLV, row, 2, (LPWSTR)U2W(g.items[0].path).c_str());
        } else {
            // 多项汇总行：路径列提示
            ListView_SetItemText(g_hLV, row, 2, (LPWSTR)L"<\u591A\u8FDB\u7A0B\u6C47\u603B>");
            
            if(isOpen){
                // 展开状态下插入子行
                for(size_t si=0;si<g.items.size();si++){
                    LVITEMW sub={}; 
                    sub.mask = LVIF_TEXT | LVIF_PARAM;
                    sub.iItem = ++row;
                    sub.iSubItem = 0;
                    std::wstring sub_pid = L"    " + std::to_wstring(g.items[si].pid);
                    sub.pszText = (LPWSTR)sub_pid.c_str();
                    sub.lParam = 0; // 子项
                    int sr = (int)SendMessage(g_hLV, LVM_INSERTITEMW, 0, (LPARAM)&sub);
                    if(sr >= 0){
                        // 子行精简：名称列使用连线符
                        ListView_SetItemText(g_hLV, sr, 1, (LPWSTR)L" |--"); 
                        ListView_SetItemText(g_hLV, sr, 2, (LPWSTR)U2W(g.items[si].path).c_str());
                    }
                }
            }
        }
    }
    if(g_selPid) swprintf(b,128,L"  PID %u \u7684\u6587\u4EF6\u53E5\u67C4\u6570: %u",g_selPid,(unsigned)v.size());
    else swprintf(b,128,L"  \u7CFB\u7EDF\u6587\u4EF6\u53E5\u67C4\u603B\u6570: %u  \u8FDB\u7A0B\u7EC4: %u  (\u53CC\u51CB\u5206\u7EC4\u884C\u53EF\u5C55\u5F00/\u6298\u53E0)",(unsigned)v.size(),(unsigned)groups.size());
    StatusW(b);

    if (topIdx > 0) {
        int count = ListView_GetItemCount(g_hLV);
        if (topIdx >= count) topIdx = count - 1;
        ListView_EnsureVisible(g_hLV, 0, FALSE);
        RECT rcItem = {0};
        if (ListView_GetItemRect(g_hLV, 0, &rcItem, LVIR_BOUNDS)) {
            int itemHeight = rcItem.bottom - rcItem.top;
            SendMessage(g_hLV, LVM_SCROLL, 0, topIdx * itemHeight);
        }
    }

    SendMessage(g_hLV, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hLV, NULL, FALSE);
}

static void FillNetFiltered(const std::vector<Net>& v){
    int topIdx = ListView_GetTopIndex(g_hLV);
    SendMessage(g_hLV, WM_SETREDRAW, FALSE, 0);
    Reset(g_hLV);
    if (Header_GetItemCount(ListView_GetHeader(g_hLV)) != 8) {
        while(ListView_DeleteColumn(g_hLV, 0)) {}
        LPCWSTR hdr[]={L"\u7C7B\u578B",L"PID",L"\u8FDB\u7A0B\u540D",L"\u672C\u5730\u5730\u5740",L"\u672C\u5730\u7AEF\u53E3",L"\u8FDC\u7A0B\u5730\u5740",L"\u8FDC\u7A0B\u7AEF\u53E3",L"\u72B6\u6001"};
        int w[]={55,55,130,200,70,200,70,90};
        for(int i=0;i<8;i++){LVCOLUMNW c={};c.mask=LVCF_FMT|LVCF_TEXT|LVCF_WIDTH;c.fmt=(i==4||i==6)?LVCFMT_RIGHT:LVCFMT_LEFT;c.pszText=(LPWSTR)hdr[i];c.cx=w[i];SendMessage(g_hLV,LVM_INSERTCOLUMNW,i,(LPARAM)&c);}
    }
    wchar_t b[64];
    for(size_t i=0;i<v.size();i++){
        const Net& n=v[i];
        if (!g_searchText.empty()) {
            std::wstring type = U2W(n.type);
            std::wstring pn = U2W(n.pn);
            std::wstring la = U2W(n.la);
            std::wstring ra = U2W(n.ra);
            std::wstring st = U2W(n.st);
            std::wstring pidStr = std::to_wstring(n.pid);
            std::wstring lpStr = std::to_wstring(n.lp);
            std::wstring rpStr = std::to_wstring(n.rp);
            if (type.find(g_searchText) == std::wstring::npos &&
                pn.find(g_searchText) == std::wstring::npos &&
                la.find(g_searchText) == std::wstring::npos &&
                ra.find(g_searchText) == std::wstring::npos &&
                st.find(g_searchText) == std::wstring::npos &&
                pidStr.find(g_searchText) == std::wstring::npos &&
                lpStr.find(g_searchText) == std::wstring::npos &&
                rpStr.find(g_searchText) == std::wstring::npos) continue;
        }
        LVITEMW lvi={}; lvi.mask=LVIF_TEXT;
        lvi.iItem=(int)i; lvi.iSubItem=0;
        { std::wstring _t=U2W(n.type); lvi.pszText=(LPWSTR)_t.c_str();
          int row=(int)SendMessage(g_hLV,LVM_INSERTITEMW,0,(LPARAM)&lvi);
          if(row<0) continue;
          lvi.iItem=row; }
        lvi.iSubItem=1; _itow(n.pid,b,10); lvi.pszText=b; SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi);
        lvi.iSubItem=2; { std::wstring _t=U2W(n.pn);  lvi.pszText=(LPWSTR)_t.c_str(); SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi); }
        lvi.iSubItem=3; { std::wstring _t=U2W(n.la);  lvi.pszText=(LPWSTR)_t.c_str(); SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi); }
        lvi.iSubItem=4; _itow(n.lp,b,10); lvi.pszText=b; SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi);
        lvi.iSubItem=5; { std::wstring _t=U2W(n.ra);  lvi.pszText=(LPWSTR)_t.c_str(); SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi); }
        lvi.iSubItem=6; _itow(n.rp,b,10); lvi.pszText=b; SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi);
        lvi.iSubItem=7; { std::wstring _t=U2W(n.st);  lvi.pszText=(LPWSTR)_t.c_str(); SendMessage(g_hLV,LVM_SETITEMW,0,(LPARAM)&lvi); }
    }
    swprintf(b,64,L"  连接数: %u", (unsigned)v.size());
    StatusW(b);
    
    if (topIdx > 0) {
        int count = ListView_GetItemCount(g_hLV);
        if (topIdx >= count) topIdx = count - 1;
        ListView_EnsureVisible(g_hLV, 0, FALSE);
        RECT rcItem = {0};
        if (ListView_GetItemRect(g_hLV, 0, &rcItem, LVIR_BOUNDS)) {
            int itemHeight = rcItem.bottom - rcItem.top;
            SendMessage(g_hLV, LVM_SCROLL, 0, topIdx * itemHeight);
        }
    }

    SendMessage(g_hLV, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hLV, NULL, FALSE);
}

static void FillProcs(const std::vector<Proc>& v){ FillProcsFiltered(v); }
static void FillNet(const std::vector<Net>& v){ FillNetFiltered(v); }
static void FillFiles(const std::vector<File>& v){ FillFilesFiltered(v); }

// FIX: 工作线程同时负责 CPU 采样 + 数据收集，完全不阻塞主线程
static DWORD WINAPI Refresh(LPVOID arg){
    RefreshArg* ra=(RefreshArg*)arg;
    HWND hwnd=ra->hwnd; int tab=ra->tab; DWORD selPid=ra->selPid;
    delete ra;
    g_busy=true;
    // 仅进程标签需要 CPU 采样（两次采样间 Sleep 300ms）
    // 文件/网络标签直接采集，不等待
    if(tab==0){
        g_cpu.Sample(); Sleep(300); g_cpu.Sample();
    }
    // 在工作线程采集全部数据
    RefreshData* d=new RefreshData();
    d->tab=tab;
    if(tab==0)      d->procs=CollProcs();
    else if(tab==1) d->nets=CollNet();
    else            d->files=CollFiles(selPid);
    g_busy=false;
    // 通知主线程渲染 UI（主线程负责 delete d）
    PostMessageW(hwnd, WMU_DATA_READY, 0, (LPARAM)d);
    return 0;
}

static void Kill(DWORD p){
    if(p==0||p==GetCurrentProcessId())return;
    // 尝试获取更多权限
    HANDLE h=OpenProcess(PROCESS_TERMINATE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,p);
    if(!h){
        // 如果获取不到权限，显示错误
        wchar_t msg[256];
        DWORD err = GetLastError();
        swprintf(msg,L"无法打开 PID %u 的进程。错误代码: %u",p,err);
        MessageBoxW(g_hMain,msg,L"错误",MB_ICONERROR|MB_OK);
        return;
    }
    
    // 获取进程名用于显示
    wchar_t procName[MAX_PATH] = L"";
    HMODULE hMod = NULL;
    DWORD cbNeeded = 0;
    if(EnumProcessModules(h, &hMod, sizeof(hMod), &cbNeeded)){
        GetModuleBaseNameW(h, hMod, procName, MAX_PATH);
    }
    
    // 确认对话框
    wchar_t m[256]; 
    if(procName[0] != L'\0') {
        swprintf(m,L"确定要结束进程 '%s' (PID %u) 吗？",procName,p);
    } else {
        swprintf(m,L"确定要结束 PID %u 吗？",p);
    }
    
    if(MessageBoxW(g_hMain,m,L"确认",MB_ICONWARNING|MB_OKCANCEL)==IDOK){
        if(TerminateProcess(h,1)){
            // 成功终止进程，等待一段时间让进程真正退出
            WaitForSingleObject(h, 1000); // 等待最多1秒
            // 刷新界面
            Reset(g_hLV);
            PostMessageW(g_hMain,WMU_REFRESH,0,0);
        } else {
            // 终止失败，显示错误
            wchar_t err_msg[256];
            DWORD err = GetLastError();
            if(procName[0] != L'\0') {
                swprintf(err_msg,L"结束进程 '%s' (PID %u) 失败。错误代码: %u",procName,p,err);
            } else {
                swprintf(err_msg,L"结束进程 (PID %u) 失败。错误代码: %u",p,err);
            }
            MessageBoxW(g_hMain,err_msg,L"错误",MB_ICONERROR|MB_OK);
        }
    }
    CloseHandle(h);
}

static DWORD GetSel(){
    int s=ListView_GetNextItem(g_hLV,-1,LVNI_SELECTED);
    if(s<0)return 0;
    wchar_t b[32]; LVITEMW lvi={};lvi.mask=LVIF_TEXT;lvi.iItem=s;lvi.iSubItem=0;lvi.pszText=b;lvi.cchTextMax=32;ListView_GetItem(g_hLV,&lvi);
    return (DWORD)_wtol(b);
}

static void OnSize(){
    RECT rc,sb; GetClientRect(g_hMain,&rc); GetClientRect(g_hSB,&sb);
    SetWindowPos(g_hTab,NULL,0,0,rc.right,30,SWP_NOZORDER);
    // 调整搜索框位置
    SetWindowPos(g_hSearch, NULL, 10, 35, 200, 20, SWP_NOZORDER);
    SetWindowPos(g_hLV,NULL,0,60,rc.right,rc.bottom-60-(sb.bottom-sb.top),SWP_NOZORDER);
}

static HMENU MakeMenu(){
    HMENU m=CreateMenu(),f=CreatePopupMenu(),v=CreatePopupMenu(),h=CreatePopupMenu();
    AppendMenuW(m,MF_POPUP,(UINT_PTR)f,L"文件(&F)");
    AppendMenuW(f,MF_STRING,IDM_REFRESH,L"刷新(&R)\tF5");
    AppendMenuW(f,MF_STRING,IDM_AUTOREF,L"实时刷新(&A)\t2秒");
    AppendMenuW(f,MF_SEPARATOR,0,NULL);
    AppendMenuW(f,MF_STRING,IDM_KILL,L"结束进程(&K)\tDel");
    AppendMenuW(f,MF_SEPARATOR,0,NULL);
    AppendMenuW(f,MF_STRING,IDM_EXIT,L"退出(&X)");
    AppendMenuW(m,MF_POPUP,(UINT_PTR)v,L"视图(&V)");
    AppendMenuW(v,MF_STRING,IDM_TAB_PROC,L"进程列表");
    AppendMenuW(v,MF_STRING,IDM_TAB_NET,L"网络连接");
    AppendMenuW(v,MF_STRING,IDM_TAB_FILES,L"打开的文件");
    AppendMenuW(m,MF_POPUP,(UINT_PTR)h,L"帮助(&H)");
    AppendMenuW(h,MF_STRING,IDM_ABOUT,L"关于");
    return m;
}

static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
        case WM_CREATE:{
            g_hMain=hwnd; 
            bool ntInitialized = InitNt();
            // Use a CJK-capable font explicitly
            g_hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
            SetMenu(hwnd,MakeMenu());
            g_hTab=CreateWindowW(WC_TABCONTROLW,L"",WS_CHILD|WS_VISIBLE|TCS_FLATBUTTONS,0,0,0,0,hwnd,NULL,NULL,NULL);
            SendMessageW(g_hTab,WM_SETFONT,(WPARAM)g_hFont,TRUE);
            TCITEMW tc={TCIF_TEXT};
            tc.pszText=(LPWSTR)L"\u8FDB\u7A0B\u5217\u8868";   TabCtrl_InsertItem(g_hTab,0,&tc);
            tc.pszText=(LPWSTR)L"\u7F51\u7EDC\u8FDE\u63A5";   TabCtrl_InsertItem(g_hTab,1,&tc);
            tc.pszText=(LPWSTR)L"\u6253\u5F00\u7684\u6587\u4EF6";  TabCtrl_InsertItem(g_hTab,2,&tc);
            
            // 创建搜索框
            g_hSearch=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                    10,35,200,20,hwnd,(HMENU)IDM_SEARCH,NULL,NULL);
            SendMessageW(g_hSearch,WM_SETFONT,(WPARAM)g_hFont,TRUE);
            SetWindowTextW(g_hSearch,L"");
            
            g_hLV=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL|WS_BORDER,0,60,0,0,hwnd,NULL,NULL,NULL);
            ListView_SetExtendedListViewStyle(g_hLV,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER);
            SendMessageW(g_hLV,WM_SETFONT,(WPARAM)g_hFont,TRUE);
            g_hSB=CreateWindowW(STATUSCLASSNAMEW,L"",WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,0,0,0,0,hwnd,NULL,NULL,NULL);
            SendMessageW(g_hSB,WM_SETFONT,(WPARAM)g_hFont,TRUE);
            g_admin=IsAdmin();
            if(!ntInitialized) {
                StatusW(g_admin?L"  管理员模式 - NTDLL函数未加载  |  F5刷新  |  Delete结束进程  |  双击进程行查看文件句柄":L"  非管理员模式，NTDLL函数未加载  |  F5刷新");
            } else {
                StatusW(g_admin?L"  管理员模式  |  F5刷新  |  Delete结束进程  |  双击进程行查看文件句柄  |  文件标签页双击分组行展开/折叠":L"  非管理员模式，建议以管理员身份运行  |  F5刷新");
            }
            // FIX-B7: 保存句柄并关闭
            { RefreshArg* ra=new RefreshArg{hwnd,g_iTab,g_selPid};
              HANDLE htInit=CreateThread(NULL,0,Refresh,ra,0,NULL);
              if(htInit) CloseHandle(htInit); else delete ra; }
            break;
        }
        // WMU_REFRESH: 启动工作线程采集数据
        case WMU_REFRESH:
            if(!g_busy){
                RefreshArg* ra=new RefreshArg{hwnd, g_iTab, g_selPid};
                HANDLE ht=CreateThread(NULL,0,Refresh,ra,0,NULL);
                if(ht) CloseHandle(ht);
                else delete ra; // 创建失败时避免泄漏
            }
            return 0;
        // WMU_DATA_READY: 工作线程采集完成，主线程渲染 UI
        case WMU_DATA_READY: {
            RefreshData* d=(RefreshData*)(LPARAM)lp;
            if(d){
                if(d->tab==0) g_cachedProcs=d->procs; // 缓存进程数据
                if(d->tab==2) g_cachedFiles=d->files; // 缓存文件数据
                Reset(g_hLV);
                switch(d->tab){
                    case 0: 
                        if (g_searchText.empty())
                            FillProcs(d->procs); 
                        else
                            FillProcsFiltered(d->procs);
                        break;
                    case 1: 
                        if (g_searchText.empty())
                            FillNet(d->nets);    
                        else
                            FillNetFiltered(d->nets);
                        break;
                    case 2: 
                        if (g_searchText.empty())
                            FillFiles(d->files); 
                        else
                            FillFilesFiltered(d->files);
                        break;
                }
                delete d;
            }
            return 0;
        }
        case WM_SIZE: OnSize(); return 0;
        case WM_COMMAND:
            switch(LOWORD(wp)){
                case IDM_REFRESH: PostMessageW(hwnd,WMU_REFRESH,0,0); break;
                case IDM_AUTOREF:{
                    g_autoRef=!g_autoRef;
                    CheckMenuItem(GetMenu(hwnd),IDM_AUTOREF,g_autoRef?MF_CHECKED:MF_UNCHECKED);
                    if(g_autoRef) SetTimer(hwnd,TIMER_AUTO_REFRESH,g_autoRefMs,NULL);
                    else KillTimer(hwnd,TIMER_AUTO_REFRESH);
                    break;
                }
                case IDM_KILL:{DWORD p=GetSel();if(p)Kill(p);break;}
                case IDM_TAB_PROC: g_iTab=0;Reset(g_hLV);PostMessageW(hwnd,WMU_REFRESH,0,0);break;
                case IDM_TAB_NET:  g_iTab=1;Reset(g_hLV);PostMessageW(hwnd,WMU_REFRESH,0,0);break;
                case IDM_TAB_FILES:g_iTab=2;Reset(g_hLV);PostMessageW(hwnd,WMU_REFRESH,0,0);break;
                case IDM_EXIT: PostMessageW(hwnd,WM_CLOSE,0,0); break;
                case IDM_ABOUT:
                    MessageBoxW(hwnd,
                        L"Process Explorer v1.0\r\n\r\n"
                        L"显示所有运行中的进程及其 CPU、内存、\r\n"
                        L"网络连接和打开的文件信息。\r\n\r\n"
                        L"快捷键: F5刷新  |  Delete结束进程  |  双击查看文件句柄",
                        L"关于", MB_ICONINFORMATION|MB_OK); break;
                case IDM_SEARCH: // 处理搜索框输入
                    if(HIWORD(wp) == EN_CHANGE) {
                        wchar_t buffer[256];
                        GetWindowTextW(g_hSearch, buffer, 256);
                        g_searchText = std::wstring(buffer);
                        
                        // 根据当前标签页重新加载数据
                        RefreshArg* ra=new RefreshArg{hwnd, g_iTab, g_selPid};
                        HANDLE ht=CreateThread(NULL,0,Refresh,ra,0,NULL);
                        if(ht) CloseHandle(ht);
                        else delete ra;
                    }
                    break;
            }return 0;
        case WM_TIMER:
            if(wp==TIMER_AUTO_REFRESH && !g_busy)
                PostMessageW(hwnd,WMU_REFRESH,0,0);
            return 0;
        case WM_NOTIFY:{
            NMHDR* nmh=(NMHDR*)lp;
            if(nmh->hwndFrom==g_hTab && nmh->code==TCN_SELCHANGE){g_iTab=TabCtrl_GetCurSel(g_hTab);Reset(g_hLV);PostMessageW(hwnd,WMU_REFRESH,0,0);}
            if(nmh->hwndFrom==g_hLV){
                if(nmh->code==NM_DBLCLK){
                    // 用 HitTest 精确获取点击行号
                    DWORD pos=GetMessagePos();
                    POINT pt={GET_X_LPARAM(pos),GET_Y_LPARAM(pos)};
                    ScreenToClient(g_hLV,&pt);
                    LVHITTESTINFO hti={}; hti.pt=pt;
                    SendMessage(g_hLV,LVM_SUBITEMHITTEST,0,(LPARAM)&hti);
                    int sel=hti.iItem;
                    if(sel>=0 && g_iTab==0){
                        // 进程标签：双击分组行切换展开/折叠
                        LVITEMW chk={}; chk.mask=LVIF_PARAM; chk.iItem=sel; chk.iSubItem=0;
                        SendMessage(g_hLV,LVM_GETITEMW,0,(LPARAM)&chk);
                        if(chk.lParam>0 && (size_t)chk.lParam<=g_procGrpNames.size()){
                            const std::string& gname=g_procGrpNames[(size_t)(chk.lParam-1)];
                            g_procGroupOpen[gname]=g_procGroupOpen.count(gname)?!g_procGroupOpen[gname]:false;
                            FillProcs(g_cachedProcs);
                        } else {
                            // 双击普通行（子行或单进程行）：跳转到文件句柄
                            DWORD p=GetSel();if(p){g_selPid=p;g_iTab=2;TabCtrl_SetCurSel(g_hTab,2);Reset(g_hLV);PostMessageW(hwnd,WMU_REFRESH,0,0);}
                        }
                    } else if(sel>=0 && g_iTab==2){
                        // 文件标签：双击分组行切换展开/折叠
                        LVITEMW chk={}; chk.mask=LVIF_PARAM; chk.iItem=sel; chk.iSubItem=0;
                        SendMessage(g_hLV,LVM_GETITEMW,0,(LPARAM)&chk);
                        if(chk.lParam>0 && (size_t)chk.lParam<=g_grpNames.size()){
                            const std::string& gname=g_grpNames[(size_t)(chk.lParam-1)];
                            g_groupOpen[gname]=g_groupOpen.count(gname)?!g_groupOpen[gname]:false;
                            FillFiles(g_cachedFiles);
                        }
                    } else if(sel>=0 && g_iTab==1){
                        // 网络标签：双击跳转到文件句柄
                        DWORD p=GetSel();if(p){g_selPid=p;g_iTab=2;TabCtrl_SetCurSel(g_hTab,2);Reset(g_hLV);PostMessageW(hwnd,WMU_REFRESH,0,0);}
                    }
                }
            }
            return 0;
        }
        case WM_KEYDOWN:
            if(wp==VK_F5)PostMessageW(hwnd,WMU_REFRESH,0,0);
            else if(wp==VK_DELETE){DWORD p=GetSel();if(p)Kill(p);} return 0;
        case WM_DESTROY: KillTimer(hwnd,TIMER_AUTO_REFRESH); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE,LPSTR,int nShow){
    // FIX-B5: WSAStartup 应在创建窗口前就就绪，避免 WM_CREATE 期间网络调用失败
    WSADATA wd; WSAStartup(MAKEWORD(2,2),&wd);
    INITCOMMONCONTROLSEX ice={sizeof(ice),ICC_WIN95_CLASSES}; InitCommonControlsEx(&ice);
    WNDCLASSW wc={}; wc.style=CS_HREDRAW|CS_VREDRAW; wc.lpfnWndProc=WndProc; wc.hInstance=hInst;
    wc.hIcon=LoadIconW(NULL,(LPCWSTR)IDI_APPLICATION); wc.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1); wc.lpszClassName=L"PEW";
    RegisterClassW(&wc);
    int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);
    HWND h=CreateWindowW(L"PEW",L"Process Explorer",WS_OVERLAPPEDWINDOW,(sw*3)/10,(sh*1)/20,(sw*7)/10,(sh*9)/10,NULL,NULL,hInst,NULL);
    if(!h) return 1;
    ShowWindow(h,nShow); UpdateWindow(h);
    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)){TranslateMessage(&msg);DispatchMessageW(&msg);}
    WSACleanup(); return (int)msg.wParam;
}