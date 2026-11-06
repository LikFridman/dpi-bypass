//go:build windows

package main

// Настройки окна, автозапуск, самообновление, консоль.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// ---------- настройки ----------

type Settings struct {
	Tray     bool   `json:"tray"`      // сворачивать в трей
	LastMode int    `json:"last_mode"` // какой режим был включён последним (для автозапуска)
	BgFile   string `json:"bg_file"`   // своя картинка фона (в папке dpi-bypass-data)
	BgDim    int    `json:"bg_dim"`    // затемнение фона, %
	BgBlur   int    `json:"bg_blur"`   // размытие фона, px
	// версия принятого пользовательского соглашения (0 - не принято) и когда
	Consent   int    `json:"consent"`
	ConsentAt string `json:"consent_at,omitempty"`
	// зашифрованный DNS выключен вручную (по умолчанию включён)
	NoDoH bool `json:"no_doh,omitempty"`
	// какие сервисы нужны (подбор и проверки - только по ним); SitesSet=false - ещё не выбирали (все)
	Sites    []string `json:"sites,omitempty"`
	SitesSet bool     `json:"sites_set,omitempty"`
}

var settings = Settings{Tray: true, LastMode: modeWithVPN, BgDim: 45}

func settingsPath() string { return filepath.Join(dataDir, "settings.json") }

func loadSettings() {
	if b, err := os.ReadFile(settingsPath()); err == nil {
		json.Unmarshal(b, &settings)
	}
	if settings.LastMode != modeNoVPN && settings.LastMode != modeWithVPN {
		settings.LastMode = modeWithVPN
	}
}

func saveSettings() {
	b, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(settingsPath(), b, 0644)
}

// ---------- консоль ----------

var (
	procAttachConsole = kernel32.NewProc("AttachConsole")
	procAllocConsole  = kernel32.NewProc("AllocConsole")
	procMessageBoxW   = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
)

// attachConsole подключает вывод к консоли, из которой запустили программу
// (exe собран как оконное приложение и своей консоли не имеет)
func attachConsole(forceNew bool) {
	// вывод уже перенаправлен в файл/канал (например, в GitHub Actions) - оставляем как есть
	if h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != syscall.InvalidHandle {
		if ft, _ := syscall.GetFileType(h); ft == syscall.FILE_TYPE_DISK || ft == syscall.FILE_TYPE_PIPE {
			out = os.Stdout
			return
		}
	}
	if forceNew {
		procAllocConsole.Call()
	} else if r, _, _ := procAttachConsole.Call(uintptr(^uint32(0))); r == 0 { // ATTACH_PARENT_PROCESS
		procAllocConsole.Call()
	}
	if f, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout, os.Stderr = f, f
		out = os.Stdout
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
		os.Stdin = f
		stdin.Reset(f)
	}
}

func messageBox(text string, yesNo bool) bool {
	if webUIActive {
		if yesNo {
			return uiConfirm(text)
		}
		uiToast(text)
		return true
	}
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("dpi-bypass")
	flags := uintptr(0x40 | 0x40000) // MB_ICONINFORMATION | MB_TOPMOST
	if yesNo {
		flags = 0x4 | 0x20 | 0x40000 // MB_YESNO | MB_ICONQUESTION | MB_TOPMOST
	}
	r, _, _ := procMessageBoxW.Call(guiHwnd, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return r == 6 // IDYES
}

// ---------- автозапуск (Планировщик заданий: с правами администратора и без окна UAC) ----------

const taskName = "dpi-bypass"

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

func autostartEnabled() bool {
	c := exec.Command("schtasks", "/Query", "/TN", taskName)
	c.SysProcAttr = hiddenProcAttr()
	return c.Run() == nil
}

func setAutostart(on bool) error {
	if !on {
		c := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
		c.SysProcAttr = hiddenProcAttr()
		if out, err := c.CombinedOutput(); err != nil && autostartEnabled() {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	exe, _ := os.Executable()
	user := os.Getenv("USERNAME")
	if d := os.Getenv("USERDOMAIN"); d != "" {
		user = d + `\` + user
	}
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>dpi-bypass: включить обход DPI при входе в Windows</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + xmlEscape(user) + `</UserId><Delay>PT15S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>` + xmlEscape(user) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEscape(exe) + `</Command><Arguments>--autostart</Arguments><WorkingDirectory>` + xmlEscape(baseDir) + `</WorkingDirectory></Exec></Actions>
</Task>`
	// файл задания - в UTF-16 с BOM
	u := utf16.Encode([]rune(xml))
	buf := make([]byte, 2+len(u)*2)
	buf[0], buf[1] = 0xFF, 0xFE
	for i, v := range u {
		buf[2+i*2], buf[3+i*2] = byte(v), byte(v>>8)
	}
	p := filepath.Join(dataDir, "autostart-task.xml")
	if err := os.WriteFile(p, buf, 0644); err != nil {
		return err
	}
	defer os.Remove(p)
	c := exec.Command("schtasks", "/Create", "/TN", taskName, "/XML", p, "/F")
	c.SysProcAttr = hiddenProcAttr()
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------- самообновление ----------

var exeBases = []string{
	"https://raw.githubusercontent.com/LikFridman/dpi-bypass/main/",
	"https://cdn.jsdelivr.net/gh/LikFridman/dpi-bypass@main/",
}

func httpGetSmall(url string, limit int64) ([]byte, error) {
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// latestVersion - номер версии exe, который лежит в репозитории
func latestVersion() (string, bool) {
	for _, b := range exeBases {
		if data, err := httpGetSmall(b+"dpi-bypass.version", 64); err == nil {
			v := strings.TrimSpace(string(data))
			if v != "" && len(v) < 20 {
				return v, true
			}
		}
	}
	return "", false
}

func versionParts(v string) []int {
	v = strings.SplitN(strings.TrimPrefix(v, "v"), "-", 2)[0]
	var p []int
	for _, x := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(x)
		p = append(p, n)
	}
	return p
}

// newerVersion: a новее b
func newerVersion(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func cleanupOldExe() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	for i := 0; i < 5; i++ {
		if err := os.Remove(exe + ".old"); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Second)
	}
}

// downloadUpdate скачивает новый exe и проверяет контрольную сумму
func downloadUpdate() (string, error) {
	exe, _ := os.Executable()
	tmp := exe + ".new"
	var lastErr error
	for _, b := range exeBases {
		sumData, err := httpGetSmall(b+"dpi-bypass.exe.sha256", 256)
		if err != nil {
			lastErr = err
			continue
		}
		want := strings.ToLower(strings.Fields(string(sumData) + " x")[0])
		cl := &http.Client{Timeout: 3 * time.Minute}
		resp, err := cl.Get(b + "dpi-bypass.exe")
		if err != nil {
			lastErr = err
			continue
		}
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return "", err
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		f.Close()
		if err != nil || resp.StatusCode != 200 {
			lastErr = fmt.Errorf("загрузка прервалась (HTTP %d)", resp.StatusCode)
			os.Remove(tmp)
			continue
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			lastErr = fmt.Errorf("контрольная сумма не совпала - файл повреждён, обновление отменено")
			os.Remove(tmp)
			continue
		}
		return tmp, nil
	}
	return "", lastErr
}

// installUpdate подменяет exe и перезапускает программу
func installUpdate(newExe string, resumeMode int) error {
	exe, _ := os.Executable()
	os.Remove(exe + ".old")
	if err := os.Rename(exe, exe+".old"); err != nil { // запущенный exe можно переименовать
		return err
	}
	if err := os.Rename(newExe, exe); err != nil {
		os.Rename(exe+".old", exe)
		return err
	}
	arg := "--resume"
	if resumeMode != 0 {
		arg = "--resume" + strconv.Itoa(resumeMode)
	}
	c := exec.Command(exe, arg)
	c.Dir = baseDir
	return c.Start()
}

// checkAndUpdate - проверка и установка обновления (консоль/окно)
func checkAndUpdate(interactive bool) {
	v, ok := latestVersion()
	if !ok {
		bad("Не удалось проверить обновления (GitHub недоступен).")
		return
	}
	if !newerVersion(v, version) {
		good("У тебя последняя версия (%s).", version)
		return
	}
	info("Доступна версия %s (у тебя %s).", v, version)
	if interactive && !askYes(fmt.Sprintf("Доступна новая версия %s (у тебя %s).\nОбновить сейчас?", v, version)) {
		return
	}
	setStatus("Downloading update…")
	p, err := downloadUpdate()
	if err != nil {
		bad("Обновление не удалось: %v", err)
		return
	}
	mode := 0
	if engRunning.Load() {
		mode = runMode
	}
	stopEngine()
	if err := installUpdate(p, mode); err != nil {
		bad("Не удалось заменить exe: %v", err)
		return
	}
	good("Обновлено до %s - перезапускаюсь.", v)
	removeTrayIcon()
	os.Exit(0)
}
