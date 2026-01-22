# Go-ProcessHider

Go实现用于Windows系统的进程隐藏工具，通过DLL注入技术将指定进程从任务管理器中隐藏。

## 效果展示

<img width="1368" height="494" alt="image" src="https://github.com/user-attachments/assets/e3770843-16a1-45e2-96ca-1a6518833bd5" />

## 技术细节

### 主要组件

- **进程枚举**: 使用`CreateToolhelp32Snapshot`和`Process32First/Next`枚举系统进程
- **DLL注入**: 通过`VirtualAllocEx`、`WriteProcessMemory`和`CreateRemoteThread`实现远程DLL注入
- **内存映射**: 使用`CreateFileMappingA`和`MapViewOfFile`实现进程间通信
- **API调用**: 直接调用Windows Native API实现底层操作

### DLL注入流程

1. 打开目标进程(`OpenProcess`)
2. 在目标进程中分配内存(`VirtualAllocEx`)
3. 将DLL路径写入目标进程内存(`WriteProcessMemory`)
4. 获取`LoadLibraryA`函数地址(`GetProcAddress`)
5. 创建远程线程执行`LoadLibraryA`加载DLL(`CreateRemoteThread`)

## 注意事项

- **管理员权限**: 程序需要管理员权限才能进行进程注入操作
- **DLL依赖**: 确保`ProcessHider.dll`与主程序在同一目录

## 功能特性

- **进程隐藏**: 通过注入DLL到任务管理器中实现进程隐藏
- **实时监控**: 持续监控任务管理器进程，发现新实例时自动注入
- **内存映射通信**: 使用内存映射在进程间共享要隐藏的进程名
- **跨进程注入**: 支持将DLL注入到运行中的任务管理器进程

## 编译方法

### 编译主程序
```bash
go build -o main.exe main.go
```

## 使用方法

1. 以管理员身份运行程序：
```bash
main.exe -p <进程名>
```

### 示例
```bash
# 隐藏notepad.exe进程
main.exe -p notepad.exe

# 隐藏cmd.exe进程
main.exe -p cmd.exe
```

### 程序输出示例
```
[+] Current Process ID: 1234
[+] Target process to hide: notepad.exe
[+] Process name 'notepad.exe' shared via memory mapping
[+] Starting process monitor for taskmgr.exe
[+] DLL Path: ProcessHider.dll (from current directory)
[+] Enter "quit" to exit
[+] Found new taskmgr.exe process (PID: 5678)
[+] Successfully injected into taskmgr.exe (PID: 5678)
[+] User activity triggered
```

## 文件结构

```
ProcessHider/
├── main.go              # 主程序入口
├── main.exe             # 编译后的可执行文件
├── ProcessHider.dll     # 注入用的DLL文件
├── go.mod               # Go模块文件
└── README.md            # 项目说明文档
```

## 法律声明

⚠️ **重要提醒**: 此工具仅用于学习和研究目的。请勿用于非法活动。作者不对使用此工具产生的任何后果承担责任。

## 免责声明

此工具仅用于教育和研究目的。使用者应当对自己的行为负责，作者不对任何滥用行为承担责任。
