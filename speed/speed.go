// Package speed - замер скорости, чтобы выбирать стратегию обхода не по «ответил ли
// сайт», а по тому, как реально грузится видео YouTube (его замедляют именно на
// серверах видео googlevideo.com).
package speed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Result - итог замера
type Result struct {
	KBps   int    `json:"kbps"`   // килобайт в секунду
	Bytes  int64  `json:"bytes"`  // сколько скачано
	Ms     int    `json:"ms"`     // сколько длилось скачивание
	Method string `json:"method"` // откуда качали
	Host   string `json:"host"`
}

// Видео для замера: долгоживущие, без возрастных ограничений
var testVideos = []string{"dQw4w9WgXcQ", "jNQXAC9IVRw"}

type ytClient struct {
	name, version, ua string
	id                int
	extra             map[string]any
}

// клиенты API плеера, которые отдают прямые ссылки на поток (как в yt-dlp)
var ytClients = []ytClient{
	{"ANDROID_VR", "1.62.27", "com.google.android.apps.youtube.vr.oculus/1.62.27 (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip", 28,
		map[string]any{"deviceMake": "Oculus", "deviceModel": "Quest 3", "androidSdkVersion": 32, "osName": "Android", "osVersion": "12L"}},
	{"IOS", "20.10.4", "com.google.ios.youtube/20.10.4 (iPhone16,2; U; CPU iOS 18_3_2 like Mac OS X;)", 5,
		map[string]any{"deviceMake": "Apple", "deviceModel": "iPhone16,2", "osName": "iPhone", "osVersion": "18.3.2.22D82"}},
}

type format struct {
	URL           string `json:"url"`
	Bitrate       int    `json:"bitrate"`
	ContentLength string `json:"contentLength"`
	MimeType      string `json:"mimeType"`
}

// videoURL получает прямую ссылку на поток googlevideo.com
func videoURL(cl *http.Client) (string, string, error) {
	var lastErr error = errors.New("нет ссылки на поток")
	for _, vid := range testVideos {
		for _, c := range ytClients {
			client := map[string]any{"clientName": c.name, "clientVersion": c.version, "hl": "en", "gl": "US"}
			for k, v := range c.extra {
				client[k] = v
			}
			body, _ := json.Marshal(map[string]any{
				"context": map[string]any{"client": client}, "videoId": vid,
				"contentCheckOk": true, "racyCheckOk": true,
			})
			req, _ := http.NewRequest("POST", "https://www.youtube.com/youtubei/v1/player?prettyPrint=false", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", c.ua)
			req.Header.Set("X-YouTube-Client-Name", strconv.Itoa(c.id))
			req.Header.Set("X-YouTube-Client-Version", c.version)
			resp, err := cl.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			var pr struct {
				StreamingData struct {
					Formats         []format `json:"formats"`
					AdaptiveFormats []format `json:"adaptiveFormats"`
				} `json:"streamingData"`
				PlayabilityStatus struct {
					Status string `json:"status"`
					Reason string `json:"reason"`
				} `json:"playabilityStatus"`
			}
			err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr)
			resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}
			best := ""
			bestRate := 0
			for _, f := range append(pr.StreamingData.AdaptiveFormats, pr.StreamingData.Formats...) {
				n, _ := strconv.ParseInt(f.ContentLength, 10, 64)
				if f.URL != "" && n > 1<<20 && strings.HasPrefix(f.MimeType, "video/") && f.Bitrate > bestRate {
					best, bestRate = f.URL, f.Bitrate
				}
			}
			if best != "" {
				return best, c.name, nil
			}
			lastErr = fmt.Errorf("%s: %s %s", c.name, pr.PlayabilityStatus.Status, pr.PlayabilityStatus.Reason)
		}
	}
	return "", "", lastErr
}

// download качает до maxBytes или до maxTime и возвращает скорость
func download(cl *http.Client, url string, maxBytes int64, maxTime time.Duration, ua string) (Result, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(maxBytes-1, 10))
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return Result{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	start := time.Now()
	buf := make([]byte, 64<<10)
	var got int64
	for got < maxBytes && time.Since(start) < maxTime {
		n, err := resp.Body.Read(buf)
		got += int64(n)
		if err != nil {
			break
		}
	}
	el := time.Since(start)
	if got == 0 {
		return Result{}, errors.New("ни одного байта")
	}
	if el < time.Millisecond {
		el = time.Millisecond
	}
	return Result{KBps: int(float64(got) / 1024 / el.Seconds()), Bytes: got, Ms: int(el.Milliseconds()), Host: resp.Request.URL.Host}, nil
}

// YouTube меряет скорость скачивания видео с googlevideo.com через cl.
// Если ссылку на поток получить не удалось - меряет главную страницу YouTube.
func YouTube(cl *http.Client, maxTime time.Duration) (Result, error) {
	u, client, err := videoURL(cl)
	if err == nil {
		ua := ""
		for _, c := range ytClients {
			if c.name == client {
				ua = c.ua
			}
		}
		r, derr := download(cl, u, 8<<20, maxTime, ua)
		r.Method = "googlevideo (" + client + ")"
		if derr == nil {
			return r, nil
		}
		err = derr
	}
	r, perr := download(cl, "https://www.youtube.com/", 4<<20, maxTime, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
	r.Method = "www.youtube.com (поток: " + err.Error() + ")"
	if perr != nil {
		return r, fmt.Errorf("видео: %v; страница: %v", err, perr)
	}
	return r, nil
}

// YouTubeVideo - только видео с googlevideo (без запасного замера страницы):
// ошибка значит, что видео через этот путь не идёт.
func YouTubeVideo(cl *http.Client, maxTime time.Duration) (Result, error) {
	return YouTubeVideoMax(cl, maxTime, 8<<20)
}

// YouTubeVideoMax - то же с ограничением объёма (экономия мобильного трафика)
func YouTubeVideoMax(cl *http.Client, maxTime time.Duration, maxBytes int64) (Result, error) {
	u, client, err := videoURL(cl)
	if err != nil {
		return Result{}, err
	}
	ua := ""
	for _, c := range ytClients {
		if c.name == client {
			ua = c.ua
		}
	}
	r, err := download(cl, u, maxBytes, maxTime, ua)
	r.Method = "googlevideo (" + client + ")"
	return r, err
}
