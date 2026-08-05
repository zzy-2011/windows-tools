# windows-tools

> 自建 Windows 小工具集，涵盖进程管理、流氓软件清理、网络防护、窗口监控等多个日常高频场景。

## 工具清单

### WindowInfoCapture.exe
窗口信息捕获工具，可实时查看目标窗口的句柄、类名、进程 ID、窗口标题、位置与尺寸等核心属性。调试 UI 自动化或分析陌生软件时非常有用。

### ProcessExplorer/
轻量级进程浏览器，基于 MinGW C++ 开发，直接读取系统 API 而非依赖外部 DLL，适合替代部分 Sysinternals Process Explorer 的基础查看需求。

### SoftCnKiller2.84/
流氓软件清理套件，支持弹窗广告定位、文件关联修复、流氓软件黑名单扫描等功能，包含针对 WinXP～Win11 各版本的注册表修复脚本。

| 子目录 | 说明 |
|--------|------|
| Data/ | 签名库、路径白名单、扫描路径配置 |
| 锁屏广告定位/ | 锁屏广告进程定位工具 |
| 文件关联修复/ | 按系统版本分类的注册表修复批处理 |

运行前建议先执行 使用前更新流氓软件黑名单.bat 更新黑名单。

### NetGuard/
基于 C++ / WinAPI 的轻量级 Windows 防火墙，支持读取 blocklist 从远程威胁情报源更新规则，可拦截指定 IP / 域名流量。

| 文件 | 说明 |
|------|------|
| NetGuard.exe | 主程序 |
| blacklist.txt | 手动维护的黑名单 |
| netguard_cache/ | 自动下载的第三方威胁情报（feodo_tracker、emerging_threats 等） |

需要管理员权限运行。

### file-monitor/
全盘文件监控 GUI 工具，实时追踪文件系统变化，适合排查未知进程的创建、修改、删除行为。

### watch-cmd/
CMD 弹出监听器，监控系统中所有新打开的 CMD 窗口并记录其输出，适用于调试或逆向分析。

| 文件 | 说明 |
|------|------|
| Watch-CmdPopups.ps1 | PowerShell 主脚本 |
| 启动CMD监听器.bat | 一键启动批处理 |

## 快速开始

Clone 仓库后按需运行对应工具，均无需安装，直接双击 exe 即可：

- WindowInfoCapture.exe
- ProcessExplorer/ProcessExplorer.exe
- NetGuard/NetGuard.exe
- SoftCnKiller2.84/SoftCnKiller.exe

## 使用注意

- 管理员权限：NetGuard、SoftCnKiller 部分功能需要以管理员身份运行。
- 安全软件拦截：流氓软件清理工具会被部分安全软件误报，运行时添加白名单或临时关闭杀软。
- 防火墙规则：NetGuard 修改系统防火墙规则，请确认操作后再执行。

## License

本仓库工具仅供个人学习与研究使用，请勿用于非法用途。
