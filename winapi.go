//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procSetConsoleOutputCP       = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP             = kernel32.NewProc("SetConsoleCP")
	procGetConsoleMode           = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode           = kernel32.NewProc("SetConsoleMode")
	procSetConsoleTitleW         = kernel32.NewProc("SetConsoleTitleW")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procShellExecuteW            = shell32.NewProc("ShellExecuteW")
)

// initConsole включает UTF-8 и ANSI-цвета в консоли Windows.
func initConsole() {
	procSetConsoleOutputCP.Call(65001)
	procSetConsoleCP.Call(65001)
	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err == nil {
		var mode uint32
		r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
		if r != 0 {
			r, _, _ = procSetConsoleMode.Call(uintptr(h), uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
			colorsOn = r != 0
		}
	}
	if t, err := syscall.UTF16PtrFromString("DPI Bypass"); err == nil {
		procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(t)))
	}
}

// isAdmin - запущен ли процесс с повышенными правами (TokenElevation)
func isAdmin() bool {
	var t syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_QUERY, &t); err != nil {
		return false
	}
	defer t.Close()
	var elevated uint32
	var n uint32
	if err := syscall.GetTokenInformation(t, 20, (*byte)(unsafe.Pointer(&elevated)), 4, &n); err != nil { // TokenElevation
		return false
	}
	return elevated != 0
}

// relaunchAsAdmin перезапускает программу с запросом UAC.
func relaunchAsAdmin(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	cwd, _ := os.Getwd()
	dir, _ := syscall.UTF16PtrFromString(cwd)
	r, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), 1)
	if r <= 32 {
		return syscall.Errno(r)
	}
	return nil
}

// --- Job Object: winws гарантированно умрёт вместе с нашей программой ---

type jobBasicLimit struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobExtendedLimit struct {
	BasicLimitInformation jobBasicLimit
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var jobHandle uintptr

func initJob() {
	h, _, _ := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return
	}
	var info jobExtendedLimit
	info.BasicLimitInformation.LimitFlags = 0x2000    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	r, _, _ := procSetInformationJobObject.Call(h, 9, // JobObjectExtendedLimitInformation
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r != 0 {
		jobHandle = h
	}
}

func attachToJob(pid int) {
	if jobHandle == 0 {
		return
	}
	const access = 0x0100 | 0x0001 // PROCESS_SET_QUOTA | PROCESS_TERMINATE
	ph, err := syscall.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return
	}
	procAssignProcessToJobObject.Call(jobHandle, uintptr(ph))
	syscall.CloseHandle(ph)
}

func hiddenProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
