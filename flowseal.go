//go:build windows

package main

// Стратегии из Flowseal/zapret-discord-youtube (MIT) - самый популярный набор под российских
// провайдеров (general, ALT..., FAKE TLS AUTO, SIMPLE FAKE). Участвуют в подборе вместе с нашими.
// Им нужны образцы ClientHello (фейк и заполнение seqovl) - они встроены в программу и
// записываются рядом с winws.

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed res/flowseal/*.bin
var flowsealBins embed.FS

// fsBin - путь к образцу в папке winws (записывается при первом обращении)
func fsBin(name string) string {
	p := zp("files/fs_" + name)
	if !fileExists(p) {
		if b, err := flowsealBins.ReadFile("res/flowseal/" + name); err == nil {
			os.MkdirAll(filepath.Dir(p), 0755)
			os.WriteFile(p, b, 0644)
		}
	}
	return p
}

// flowsealStrategies - параметры профилей TCP 443 из .bat Flowseal (без --ip-id и списков)
func flowsealStrategies() []Strategy {
	g := fsBin("tls_clienthello_www_google_com.bin")
	p4 := fsBin("tls_clienthello_4pda_to.bin")
	sf := fsBin("tls_clienthello_www_sferum_ru.bin")
	return []Strategy{
		{"f1", "Flowseal general: multisplit seqovl 568", []string{"--dpi-desync=multisplit", "--dpi-desync-split-seqovl=568", "--dpi-desync-split-pos=1", "--dpi-desync-split-seqovl-pattern=" + p4}},
		{"f2", "Flowseal ALT: fake + fakedsplit, ts", []string{"--dpi-desync=fake,fakedsplit", "--dpi-desync-repeats=6", "--dpi-desync-fooling=ts", "--dpi-desync-fakedsplit-pattern=0x00", "--dpi-desync-fake-tls=" + g}},
		{"f3", "Flowseal ALT2: multisplit seqovl 652", []string{"--dpi-desync=multisplit", "--dpi-desync-split-seqovl=652", "--dpi-desync-split-pos=2", "--dpi-desync-split-seqovl-pattern=" + g}},
		{"f4", "Flowseal ALT3: fake + hostfakesplit (ya.ru)", []string{"--dpi-desync=fake,hostfakesplit", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru", "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1", "--dpi-desync-fooling=ts"}},
		{"f5", "Flowseal ALT4: fake + multisplit, badseq 1000", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=1000", "--dpi-desync-fake-tls=" + g}},
		{"f6", "Flowseal ALT6: multisplit seqovl 681", []string{"--dpi-desync=multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-split-seqovl-pattern=" + g}},
		{"f7", "Flowseal ALT7: multisplit по sniext, seqovl 679", []string{"--dpi-desync=multisplit", "--dpi-desync-split-pos=2,sniext+1", "--dpi-desync-split-seqovl=679", "--dpi-desync-split-seqovl-pattern=" + g}},
		{"f8", "Flowseal ALT8: fake без изменений, badseq 2", []string{"--dpi-desync=fake", "--dpi-desync-fake-tls-mod=none", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2"}},
		{"f9", "Flowseal ALT9: hostfakesplit (ozon.ru)", []string{"--dpi-desync=hostfakesplit", "--dpi-desync-repeats=4", "--dpi-desync-fooling=ts,md5sig", "--dpi-desync-hostfakesplit-mod=host=ozon.ru"}},
		{"f10", "Flowseal ALT10: fake 4pda, ts", []string{"--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=ts", "--dpi-desync-fake-tls=" + p4}},
		{"f11", "Flowseal ALT11: fake + multisplit seqovl 664", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=664", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=8", "--dpi-desync-split-seqovl-pattern=" + sf, "--dpi-desync-fake-tls=" + sf}},
		{"f12", "Flowseal ALT12: hostfakesplit (google)", []string{"--dpi-desync=hostfakesplit", "--dpi-desync-fooling=ts", "--dpi-desync-hostfakesplit-mod=host=www.google.com"}},
		{"f13", "Flowseal FAKE TLS AUTO ALT: fake + fakedsplit", []string{"--dpi-desync=fake,fakedsplit", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2", "--dpi-desync-repeats=8", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
		{"f14", "Flowseal FAKE TLS AUTO ALT2: fake + multisplit seqovl", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=10000000", "--dpi-desync-repeats=8", "--dpi-desync-split-seqovl-pattern=" + g, "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
		{"f15", "Flowseal FAKE TLS AUTO ALT3: то же, ts", []string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=8", "--dpi-desync-split-seqovl-pattern=" + g, "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"}},
		{"f16", "Flowseal SIMPLE FAKE ALT: fake google, badseq 2", []string{"--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=2", "--dpi-desync-fake-tls=" + g}},
	}
}

var (
	fsCacheDir string
	fsCache    []Strategy
)

// fsList - стратегии Flowseal (пути к образцам - в текущей папке winws)
func fsList() []Strategy {
	if fsCache == nil || fsCacheDir != zapDir {
		fsCache, fsCacheDir = flowsealStrategies(), zapDir
	}
	return fsCache
}

// zapret1Strategies - все стратегии для winws: наши и Flowseal
func zapret1Strategies() []Strategy { return append(append([]Strategy{}, strategies...), fsList()...) }
