package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPrivateStoreJSONSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	writeStoreFile(t, target, []byte(`{"a":1}`))
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不允许创建符号链接，跳过: %v", err)
	}
	var v map[string]int
	if err := readPrivateStoreJSON(link, &v, "test"); err == nil {
		t.Fatal("符号链接必须被拒绝")
	}
}

func TestReadPasswordDataValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password.json")
	writeStoreFile(t, path, []byte(`{"passwordHash":"secret"}`))
	pwd, err := readPasswordData(path)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if pwd.PasswordHash != "secret" {
		t.Fatalf("unexpected hash %q", pwd.PasswordHash)
	}
}

func TestReadPasswordDataMissingIsNotExist(t *testing.T) {
	_, err := readPasswordData(filepath.Join(t.TempDir(), "password.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestValidateLoadedGlobalConfig(t *testing.T) {
	absDir := t.TempDir()
	cases := []struct {
		name string
		cfg  *GlobalConfig
		ok   bool
	}{
		{"nil", nil, false},
		{"empty", &GlobalConfig{}, true},
		{"bad-current-user", &GlobalConfig{CurrentUser: "../evil"}, false},
		{"relative-mcdir", &GlobalConfig{MinecraftDir: "relative\\dir"}, false},
		{"control-mcdir", &GlobalConfig{MinecraftDir: absDir + "\x00evil"}, false},
		{"valid-mcdir", &GlobalConfig{MinecraftDir: absDir}, true},
		{"maxmem-overflow", &GlobalConfig{MaxMemory: maxMemoryMB + 1}, false},
		{"minmem-underflow", &GlobalConfig{MinMemory: minMemoryMB - 1}, false},
		{"min-gt-max", &GlobalConfig{MinMemory: 4096, MaxMemory: 2048}, false},
		{"valid-memory", &GlobalConfig{MinMemory: 1024, MaxMemory: 4096}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLoadedGlobalConfig(tc.cfg)
			if tc.ok && err != nil {
				t.Fatalf("expected pass, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected reject, cfg=%+v", tc.cfg)
			}
		})
	}
}

func TestValidateLoadedUserConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  *UserConfig
		ok   bool
	}{
		{"nil", nil, false},
		{"empty", &UserConfig{}, true},
		{"bad-version", &UserConfig{SelectedVersion: "../escape"}, false},
		{"valid-version", &UserConfig{SelectedVersion: "1.20.4"}, true},
		{"bad-color", &UserConfig{ThemeColor: "</script>"}, false},
		{"valid-color", &UserConfig{ThemeColor: "cyan"}, true},
		{"control-background", &UserConfig{BackgroundImage: "C:\\x\x00y.png"}, false},
		{"valid-background", &UserConfig{BackgroundImage: filepath.Join(t.TempDir(), "bg.png")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLoadedUserConfig(tc.cfg)
			if tc.ok && err != nil {
				t.Fatalf("expected pass, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected reject, cfg=%+v", tc.cfg)
			}
		})
	}
}

func TestValidateLoadedUserConfigTrimsTheme(t *testing.T) {
	cfg := &UserConfig{ThemeColor: "  green  "}
	if err := validateLoadedUserConfig(cfg); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if cfg.ThemeColor != "green" {
		t.Fatalf("expected trimmed green, got %q", cfg.ThemeColor)
	}
}

func TestValidateLoadedGlobalConfigRejectsLongControlCurrentUser(t *testing.T) {
	long := strings.Repeat("a", 65)
	if err := validateLoadedGlobalConfig(&GlobalConfig{CurrentUser: long}); err == nil {
		t.Fatal("超长用户名必须被拒绝")
	}
}
