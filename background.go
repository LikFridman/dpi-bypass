//go:build windows

package main

// Свой фон окна: картинка хранится только на этом компьютере (dpi-bypass-data\background.*).

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var bgTypes = map[string]string{"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// saveBackground принимает картинку в виде data:image/...;base64,...
func saveBackground(dataURL string) error {
	head, data, ok := strings.Cut(dataURL, ",")
	if !ok || !strings.HasPrefix(head, "data:") || !strings.HasSuffix(head, ";base64") {
		return fmt.Errorf("это не картинка")
	}
	ext, ok := bgTypes[strings.TrimSuffix(strings.TrimPrefix(head, "data:"), ";base64")]
	if !ok {
		return fmt.Errorf("нужен JPG, PNG, WebP или GIF")
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("файл повреждён")
	}
	if len(raw) > 15<<20 {
		return fmt.Errorf("картинка больше 15 МБ")
	}
	if settings.BgFile != "" {
		os.Remove(filepath.Join(dataDir, settings.BgFile))
	}
	name := "background." + ext
	if err := os.WriteFile(filepath.Join(dataDir, name), raw, 0644); err != nil {
		return err
	}
	settings.BgFile = name
	saveSettings()
	return nil
}

func bgInfo() map[string]any {
	res := map[string]any{"url": "", "dim": settings.BgDim, "blur": settings.BgBlur}
	if settings.BgFile == "" {
		return res
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, settings.BgFile))
	if err != nil {
		return res
	}
	mime := "image/jpeg"
	for m, e := range bgTypes {
		if strings.HasSuffix(settings.BgFile, "."+e) {
			mime = m
		}
	}
	res["url"] = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(raw)
	return res
}
