//go:build windows

package main

import (
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// ---------- буфер обмена ----------

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procIsWow64Process2  = kernel32.NewProc("IsWow64Process2")
	procRtlMoveMemory    = kernel32.NewProc("RtlMoveMemory")
)

func copyToClipboard(text string) bool {
	u, err := syscall.UTF16FromString(text)
	if err != nil {
		return false
	}
	if r, _, _ := procOpenClipboard.Call(0); r == 0 {
		return false
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	h, _, _ := procGlobalAlloc.Call(0x0002, uintptr(len(u)*2)) // GMEM_MOVEABLE
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return false
	}
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)*2))
	procGlobalUnlock.Call(h)
	r, _, _ := procSetClipboardData.Call(13, h) // CF_UNICODETEXT
	return r != 0
}

// ---------- архитектура ----------

// isARM64 - Windows на ARM-процессоре (наш x64 exe там работает через эмуляцию,
// а драйвер WinDivert для ARM64 официально не подписан)
func isARM64() bool {
	if procIsWow64Process2.Find() != nil {
		return false
	}
	var proc, native uint16
	r, _, _ := procIsWow64Process2.Call(uintptr(^uintptr(0)), uintptr(unsafe.Pointer(&proc)), uintptr(unsafe.Pointer(&native)))
	return r != 0 && native == 0xAA64 // IMAGE_FILE_MACHINE_ARM64
}

// ---------- Защитник Windows ----------

// defenderHelp помогает добавить папку программы в исключения Защитника.
// Сама программа настройки безопасности не меняет: открывает нужную страницу,
// а путь кладёт в буфер обмена - добавляет пользователь.
func defenderHelp() {
	title("Защитник Windows")
	say("Защитник иногда считает winws и драйвер WinDivert опасными: они перехватывают сетевые")
	say("пакеты - так же, как это делают и вредоносные программы. Это ложное срабатывание.")
	say("")
	if miss := missingZapretFiles(); len(miss) > 0 {
		warn("Сейчас не хватает файлов: %s - скорее всего их удалил Защитник.", strings.Join(miss, ", "))
	} else {
		good("Все файлы winws на месте.")
	}
	say("")
	say("Чтобы Защитник их не трогал, добавь папку в исключения:")
	if copyToClipboard(baseDir) {
		good("Путь уже скопирован в буфер обмена: %s", baseDir)
	} else {
		info("Путь: %s", baseDir)
	}
	say("  1. Сейчас откроется «Защита от вирусов и угроз» -> «Управление настройками».")
	say("  2. Прокрути до «Исключения» -> «Добавление или удаление исключений».")
	say("  3. «Добавить исключение» -> «Папка» -> вставь путь (Ctrl+V) -> «Выбор папки».")
	say("")
	say("Если файлы уже в карантине: «Журнал защиты» -> найди winws/WinDivert -> «Действия» -> «Восстановить».")
	if askYes("Открыть настройки Защитника?") {
		openURL("windowsdefender://threatsettings")
	}
	if askYes("Открыть журнал защиты (карантин)?") {
		openURL("windowsdefender://threat")
	}
}

// explainWinwsExit переводит ошибку winws на понятный язык
func explainWinwsExit(output string) {
	o := strings.ToLower(output)
	switch {
	case len(missingZapretFiles()) > 0:
		bad("Пропали файлы winws: %s", strings.Join(missingZapretFiles(), ", "))
		say("      Почти наверняка их удалил антивирус. Пункт меню 6 - как вернуть и добавить в исключения.")
	case strings.Contains(o, "error opening filter"):
		bad("Драйвер WinDivert не загрузился.")
		switch {
		case isARM64():
			say("      Это Windows на ARM-процессоре - для неё драйвер WinDivert официально не подписан.")
		case strings.Contains(o, "access") || strings.Contains(o, "denied") || strings.Contains(o, "permission"):
			say("      Нет доступа - драйвер блокирует антивирус или он занят другой программой обхода.")
		default:
			say("      Частые причины: антивирус блокирует драйвер (пункт 6), запущен другой обход (GoodbyeDPI,")
			say("      zapret, служба «zapret»), включён Secure Boot со старыми обновлениями Windows.")
		}
	case strings.Contains(o, "could not") || strings.Contains(o, "cannot access"):
		bad("winws не смог прочитать свои файлы. Попробуй пункт 5 (подобрать заново) или удали папку dpi-bypass-data.")
	}
}

// conflictingServices ищет службы других обходчиков, которые держат свой winws/WinDivert
func conflictingServices() []string {
	var found []string
	for _, name := range []string{"zapret", "winws1", "winws2", "GoodbyeDPI", "goodbyedpi", "zapret-discord-youtube", "ByeDPI"} {
		c := exec.Command("sc", "query", name)
		c.SysProcAttr = hiddenProcAttr()
		o, err := c.Output()
		if err == nil && strings.Contains(string(o), "RUNNING") {
			found = append(found, name)
		}
	}
	return found
}

func stopServices(names []string) {
	for _, n := range names {
		c := exec.Command("sc", "stop", n)
		c.SysProcAttr = hiddenProcAttr()
		c.Run()
	}
}
