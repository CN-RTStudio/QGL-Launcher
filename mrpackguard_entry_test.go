package main

import (
	"testing"
)

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
