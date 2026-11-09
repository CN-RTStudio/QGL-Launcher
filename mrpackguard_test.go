package main

import (
	"testing"
)

// files[].path 落盘路径策略：核心是堵住“写到实例目录根部 / QGL 私有目录 / 非法扩展名”。

func TestSecureMrpackDestRelFilesPolicy(t *testing.T) {
	ok := []string{
		"mods/foo.jar",
		"mods/foo.jar.disabled",
		"mods/1.20/bar.zip",
		"resourcepacks/pack.zip",
		"shaderpacks/s.zip",
		"config/some-mod/config.json",
		"kubejs/startup_scripts/thing.js",
		"defaultconfigs/foo.txt",
	}
	for _, p := range ok {
		if got, why := secureMrpackDestRel(p); why != mrpRejectNone {
			t.Errorf("路径应通过却被拒 %q -> %q (%s)", p, got, why)
		}
	}

	bad := map[string]string{
		"1.20.1.json":            mrpRejectRootFile, // 覆盖启动 profile
		"1.20.1.jar":             mrpRejectRootFile, // 根部可执行
		"options.txt":            mrpRejectRootFile, // files[] 不允许根部数据文件
		"QGL/config.json":        mrpRejectPrivateDir,
		"QGL/umfs_cache.json":    mrpRejectPrivateDir,
		"qgl/x.json":             mrpRejectRootFile, // 大小写不一致也不允许（不在白名单）
		"mods/evil.exe":          mrpRejectBadExt,
		"mods/evil.bat":          mrpRejectBadExt,
		"resourcepacks/evil.png": mrpRejectBadExt,
		"shaderpacks/evil.jar":   mrpRejectBadExt,
		"lib/evil.exe":           mrpRejectRootFile, // 非白名单子目录整体拒绝
	}
	for p, want := range bad {
		_, why := secureMrpackDestRel(p)
		if why != want {
			t.Errorf("路径 %q 拒绝码 = %q, 期望 %q", p, why, want)
		}
	}
}

func TestCleanMrpackPathSegments(t *testing.T) {
	bad := map[string]string{
		"":               mrpRejectEmptyPath,
		"mods/a\x00.jar": mrpRejectControl,
		"mods/a\tb.jar":  mrpRejectControl,
		"mods\\a.jar":    mrpRejectBackslash,
		"/mods/a.jar":    mrpRejectAbsolute,
		"C:a.jar":        mrpRejectDrive,
		"mods/../a.jar":  mrpRejectBadSegment,
		"mods/./a.jar":   mrpRejectBadSegment,
		"mods//a.jar":    mrpRejectBadSegment,
		"mods/CON.jar":   mrpRejectBadSegment, // 保留设备名
		"mods/a.jar ":    mrpRejectBadSegment, // 段尾空格
		"mods/a.jar.":    mrpRejectBadSegment, // 段尾点
	}
	for p, want := range bad {
		_, why := cleanMrpackPathSegments(p)
		if why == mrpRejectNone {
			t.Errorf("路径应被拒却通过 %q（期望 %q）", p, want)
		}
	}

	got, why := cleanMrpackPathSegments("mods/sub/a.jar")
	if why != mrpRejectNone || got != "mods/sub/a.jar" {
		t.Errorf("合法路径被破坏: got=%q why=%q", got, why)
	}
}

// overrides 策略比 files[] 宽：允许根部数据文件，但拒绝根部启动配置 / 可执行。

func TestMrpackOverridePolicy(t *testing.T) {
	allow := []string{"options.txt", "servers.dat", "mods/a.jar", "config/x.json", "resourcepacks/p.zip"}
	for _, p := range allow {
		if why := mrpackOverridePolicy(p, false); why != mrpRejectNone {
			t.Errorf("覆写条目应允许却被拒 %q -> %s", p, why)
		}
	}
	deny := map[string]string{
		"1.20.json":       mrpRejectRootSensitive,
		"run.jar":         mrpRejectRootSensitive,
		"start.bat":       mrpRejectRootSensitive,
		"QGL/config.json": mrpRejectPrivateDir,
		"QGL":             mrpRejectPrivateDir,
		"mods/x.exe":      mrpRejectBadExt,
		"lib/tool.exe":    mrpRejectBadExt,
		"scripts/x.jar":   mrpRejectBadExt,
	}
	for p, want := range deny {
		isDir := p == "QGL"
		if why := mrpackOverridePolicy(p, isDir); why != want {
			t.Errorf("覆写条目 %q 拒绝码 = %q, 期望 %q", p, why, want)
		}
	}
}

func TestValidateMrpackHash(t *testing.T) {
	full512 := repeatHex('a', 128)
	if why := validateMrpackHash(map[string]string{"sha512": full512}); why != mrpRejectNone {
		t.Errorf("合法 sha512 被拒: %s", why)
	}
	if why := validateMrpackHash(map[string]string{"sha1": "0123456789abcdef0123456789abcdef01234567"}); why != mrpRejectNone {
		t.Errorf("合法 sha1 被拒: %s", why)
	}
	bad := []map[string]string{
		nil,
		{},
		{"md5": repeatHex('a', 32)},
		{"sha1": "xyz"},
		{"sha1": repeatHex('g', 40)}, // 非十六进制
		{"sha512": repeatHex('a', 64)},
	}
	for i, h := range bad {
		if why := validateMrpackHash(h); why == mrpRejectNone {
			t.Errorf("非法哈希用例 %d 应被拒", i)
		}
	}
}

func repeatHex(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
