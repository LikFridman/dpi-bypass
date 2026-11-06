//go:build windows

package main

// Сведения об устройстве для отчётов: ключ устройства (для группировки отчётов одного компьютера),
// версия Windows, процессор, память, масштаб экрана. Ничего личного: имя компьютера, имя пользователя,
// MAC-адреса не отправляются; MachineGuid уходит только хэшем.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	pRegGetValueW   = advapi32.NewProc("RegGetValueW")
	pGlobalMemoryEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
)

const (
	hkeyLocalMachine = 0x80000002
	rrfRtRegSz       = 0x00000002
	rrfRtRegDword    = 0x00000010
	rrfSubkeyWow6464 = 0x00010000
)

// regStr читает строку из HKLM (64-битное представление реестра)
func regStr(path, name string) string {
	var size uint32
	p, n := u16(path), u16(name)
	r, _, _ := pRegGetValueW.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(n)),
		rrfRtRegSz|rrfSubkeyWow6464, 0, 0, uintptr(unsafe.Pointer(&size)))
	if r != 0 || size < 2 || size > 4096 {
		return ""
	}
	buf := make([]uint16, size/2+1)
	r, _, _ = pRegGetValueW.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(n)),
		rrfRtRegSz|rrfSubkeyWow6464, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

var (
	devIDOnce sync.Once
	devID     string
)

// deviceID - хэш MachineGuid Windows (у каждой установки Windows свой, не меняется при обновлении программы)
func deviceID() string {
	devIDOnce.Do(func() {
		g := regStr(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
		if g == "" {
			g = "nomguid:" + baseDir
		}
		h := sha256.Sum256([]byte("dpi-bypass:" + g))
		devID = "w-" + hex.EncodeToString(h[:8])
	})
	return devID
}

func ramMB() (total, free uint64) {
	var m struct {
		Length                                    uint32
		MemoryLoad                                uint32
		TotalPhys, AvailPhys, TotalPageFile       uint64
		AvailPageFile, TotalVirtual, AvailVirtual uint64
		AvailExtendedVirtual                      uint64
	}
	m.Length = uint32(unsafe.Sizeof(m))
	if r, _, _ := pGlobalMemoryEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 0, 0
	}
	return m.TotalPhys >> 20, m.AvailPhys >> 20
}

// deviceInfo - дополнительные поля раздела device в отчёте
func deviceInfo() map[string]any {
	cv := `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	edition := regStr(cv, "ProductName")
	if windowsBuild() >= 22000 && len(edition) > 10 && edition[:10] == "Windows 10" {
		edition = "Windows 11" + edition[10:] // ProductName на Windows 11 по-прежнему пишет «Windows 10»
	}
	total, free := ramMB()
	return map[string]any{
		"edition":          edition,
		"display_version":  regStr(cv, "DisplayVersion"),
		"cpu":              regStr(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"),
		"manufacturer":     regStr(`HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"),
		"model":            regStr(`HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"),
		"ram_mb":           total,
		"ram_free_mb":      free,
		"dpi":              systemDPI(),
		"locale":           regStr(`SYSTEM\CurrentControlSet\Control\Nls\Language`, "InstallLanguage"),
		"webview2_version": regStr(`SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`, "pv"),
	}
}

// ---------- история действий в окне ----------

var (
	actMu   sync.Mutex
	actions []string
)

func recordAction(s string) {
	if len(s) > 120 {
		s = s[:120]
	}
	actMu.Lock()
	actions = append(actions, time.Now().Format("15:04:05")+" "+s)
	if len(actions) > 80 {
		actions = actions[len(actions)-80:]
	}
	actMu.Unlock()
}

func actionsCopy() []string {
	actMu.Lock()
	defer actMu.Unlock()
	return append([]string{}, actions...)
}
