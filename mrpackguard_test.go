package main

import "testing"

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
		"1.20.1.json":                mrpRejectRootFile, // 覆盖启动 profile
		"1.20.1.jar":                 mrpRejectRootFile, // 根部可执行
		"options.txt":                mrpRejectRootFile, // files[] 不允许根部数据文件
		"QGL/config.json":            mrpRejectPrivateDir,
		"QGL/umfs_cache.json":        mrpRejectPrivateDir,
		"qgl/x.json":                 mrpRejectRootFile, // 大小写不一致也不允许（不在白名单）
		"mods/evil.exe":              mrpRejectBadExt,
		"mods/evil.bat":              mrpRejectBadExt,
		"resourcepacks/evil.png":     mrpRejectBadExt,
		"shaderpacks/evil.jar":       mrpRejectBadExt,
		"lib/evil.exe":               mrpRejectRootFile, // 非白名单子目录整体拒绝
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
		"":                mrpRejectEmptyPath,
		"mods/a\x00.jar":  mrpRejectControl,
		"mods/a\tb.jar":   mrpRejectControl,
		"mods\\a.jar":     mrpRejectBackslash,
		"/mods/a.jar":     mrpRejectAbsolute,
		"C:a.jar":         mrpRejectDrive,
		"mods/../a.jar":   mrpRejectBadSegment,
		"mods/./a.jar":    mrpRejectBadSegment,
		"mods//a.jar":     mrpRejectBadSegment,
		"mods/CON.jar":    mrpRejectBadSegment, // 保留设备名
		"mods/a.jar ":     mrpRejectBadSegment, // 段尾空格
		"mods/a.jar.":     mrpRejectBadSegment, // 段尾点
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
		"1.20.json":      mrpRejectRootSensitive,
		"run.jar":        mrpRejectRootSensitive,
		"start.bat":      mrpRejectRootSensitive,
		"QGL/config.json": mrpRejectPrivateDir,
		"QGL":            mrpRejectPrivateDir,
		"mods/x.exe":     mrpRejectBadExt,
		"lib/tool.exe":   mrpRejectBadExt,
		"scripts/x.jar":  mrpRejectBadExt,
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

func TestNormalizeMrpackDownloads(t *testing.T) {
	good := []string{"https://cdn.modrinth.com/a/a.jar", "  https://cdn.modrinth.com/b/b.jar  "}
	if out, why := normalizeMrpackDownloads(good); why != mrpRejectNone {
		t.Errorf("合法镜像被拒: %s", why)
	} else if len(out) != 2 {
		t.Errorf("合法镜像数量错误: %d", len(out))
	}

	cases := []struct {
		urls []string
		want string
	}{
		{nil, mrpRejectNoDownload},
		{[]string{}, mrpRejectNoDownload},
		{[]string{"  "}, mrpRejectNoDownload},
		{[]string{"http://cdn.modrinth.com/a.jar"}, mrpRejectURLScheme},
		{[]string{"https://user:pass@cdn.modrinth.com/a.jar"}, mrpRejectURLUserInfo},
		{[]string{"https://127.0.0.1/a.jar"}, mrpRejectURLPrivate},
		{[]string{"https://169.254.169.254/a.jar"}, mrpRejectURLPrivate},
		{[]string{"https:///a.jar"}, mrpRejectURLHost},
		{[]string{"https://cdn.modrinth.com/a", "https://cdn.modrinth.com/a"}, mrpRejectURLDup},
	}
	for i, c := range cases {
		if _, why := normalizeMrpackDownloads(c.urls); why != c.want {
			t.Errorf("镜像用例 %d 拒绝码 = %q, 期望 %q", i, why, c.want)
		}
	}

	many := make([]string, maxMrpackMirrorsPerFile+1)
	for i := range many {
		many[i] = "https://cdn.modrinth.com/x/" + itoa(i) + ".jar"
	}
	if _, why := normalizeMrpackDownloads(many); why != mrpRejectTooManyURLs {
		t.Errorf("镜像超量应拒绝，得到 %q", why)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestValidateMrpackDependencies(t *testing.T) {
	if why := validateMrpackDependencies(map[string]string{
		"minecraft": "1.20.1", "fabric-loader": "0.16.10",
	}); why != mrpRejectNone {
		t.Errorf("合法依赖被拒: %s", why)
	}
	for _, deps := range []map[string]string{
		{"unknown-loader": "1"},
		{"minecraft": "../evil"},
		{"minecraft": "a/b"},
		{"forge": ""},
	} {
		if why := validateMrpackDependencies(deps); why == mrpRejectNone {
			t.Errorf("非法依赖应被拒: %v", deps)
		}
	}
}

func validMrpackFile(path string) ModrinthModpackFile {
	return ModrinthModpackFile{
		Path:      path,
		Hashes:    map[string]string{"sha512": repeatHex('a', 128)},
		Downloads: []string{"https://cdn.modrinth.com/p/" + safeSuffix(path)},
		FileSize:  10,
	}
}

func safeSuffix(p string) string {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			out = append(out, '_')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

func TestValidateMrpackManifest(t *testing.T) {
	good := &ModrinthModpackManifest{
		FormatVersion: 1,
		Game:          "minecraft",
		Name:          "My Pack",
		Dependencies:  map[string]string{"minecraft": "1.20.1"},
		Files: []ModrinthModpackFile{
			validMrpackFile("mods/a.jar"),
			validMrpackFile("config/m.json"),
		},
	}
	if err := validateMrpackManifest(good); err != nil {
		t.Fatalf("合法清单应通过: %v", err)
	}

	t.Run("bad format", func(t *testing.T) {
		m := *good
		m.FormatVersion = 2
		if err := validateMrpackManifest(&m); err == nil {
			t.Error("formatVersion=2 应拒绝")
		}
	})
	t.Run("bad game", func(t *testing.T) {
		m := *good
		m.Game = "terraria"
		if err := validateMrpackManifest(&m); err == nil {
			t.Error("game 非 minecraft 应拒绝")
		}
	})
	t.Run("profile overwrite", func(t *testing.T) {
		m := *good
		m.Files = []ModrinthModpackFile{validMrpackFile("1.20.1.json")}
		if err := validateMrpackManifest(&m); err == nil {
			t.Error("files[] 覆盖根部启动配置应拒绝（RCE 链）")
		}
	})
	t.Run("negative size", func(t *testing.T) {
		m := *good
		f := validMrpackFile("mods/b.jar")
		f.FileSize = -1
		m.Files = []ModrinthModpackFile{f}
		if err := validateMrpackManifest(&m); err == nil {
			t.Error("负 fileSize 应拒绝")
		}
	})
	t.Run("too many files", func(t *testing.T) {
		m := *good
		m.Files = make([]ModrinthModpackFile, maxMrpackIndexFiles+1)
		for i := range m.Files {
			m.Files[i] = validMrpackFile("mods/m" + itoa(i) + ".jar")
		}
		if err := validateMrpackManifest(&m); err == nil {
			t.Error("files 超量应拒绝")
		}
	})
}
