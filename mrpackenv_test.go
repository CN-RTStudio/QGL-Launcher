package main

import (
	"reflect"
	"testing"
)

func TestNormalizeMrpackEnvSide(t *testing.T) {
	cases := map[string]string{
		"required":    mrpackEnvRequired,
		"  OPTIONAL ": mrpackEnvOptional,
		"UnSuPpOrTeD": mrpackEnvUnsupported,
		"":            "",
		"weird":       "",
		"required ":  mrpackEnvRequired,
	}
	for in, want := range cases {
		if got := normalizeMrpackEnvSide(in); got != want {
			t.Errorf("normalizeMrpackEnvSide(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMrpackClientWanted(t *testing.T) {
	want := []struct {
		name string
		env  map[string]string
		keep bool
	}{
		{"nil 视为两端都要", nil, true},
		{"空 map 视为两端都要", map[string]string{}, true},
		{"只有 server 键", map[string]string{"server": "required"}, true},
		{"client required", map[string]string{"client": "required"}, true},
		{"client optional", map[string]string{"client": "optional"}, true},
		{"client unsupported", map[string]string{"client": "unsupported"}, false},
		{"大小写不敏感 unsupported", map[string]string{"client": "UNSUPPORTED"}, false},
		{"未知取值保守保留", map[string]string{"client": "maybe"}, true},
		{"client 空串保留", map[string]string{"client": ""}, true},
	}
	for _, c := range want {
		if got := mrpackClientWanted(c.env); got != c.keep {
			t.Errorf("%s: mrpackClientWanted=%v want %v", c.name, got, c.keep)
		}
	}
}

func envFile(path, client string) ModrinthModpackFile {
	f := ModrinthModpackFile{Path: path, FileSize: 1, Downloads: []string{"https://x.example/a"}}
	if client != "" {
		f.Env = map[string]string{"client": client}
	}
	return f
}

func TestPlanClientMrpackFilesFiltersServerOnly(t *testing.T) {
	files := []ModrinthModpackFile{
		envFile("mods/a.jar", "required"),
		envFile("mods/server-only.jar", "unsupported"),
		envFile("mods/b.jar", "optional"),
		envFile("mods/server-only2.jar", "unsupported"),
		envFile("mods/c.jar", ""), // 无 env -> 装
	}
	sel := planClientMrpackFiles(files)
	if !reflect.DeepEqual(sel.Kept, []int{0, 2, 4}) {
		t.Fatalf("Kept=%v want [0 2 4]", sel.Kept)
	}
	if !reflect.DeepEqual(sel.SkippedEnv, []int{1, 3}) {
		t.Fatalf("SkippedEnv=%v want [1 3]", sel.SkippedEnv)
	}
	if len(sel.SkippedDup) != 0 {
		t.Fatalf("不应有重复跳过，实际 %v", sel.SkippedDup)
	}
	if sel.Count() != 3 {
		t.Fatalf("Count=%d want 3", sel.Count())
	}
}

func TestPlanClientMrpackFilesDedupByPath(t *testing.T) {
	files := []ModrinthModpackFile{
		envFile("mods/a.jar", "required"),
		envFile("mods/a.jar", "required"), // 完全同路径，保留首个
		envFile("mods/b.jar", "optional"),
	}
	sel := planClientMrpackFiles(files)
	if !reflect.DeepEqual(sel.Kept, []int{0, 2}) {
		t.Fatalf("Kept=%v want [0 2]", sel.Kept)
	}
	if !reflect.DeepEqual(sel.SkippedDup, []int{1}) {
		t.Fatalf("SkippedDup=%v want [1]", sel.SkippedDup)
	}
}

func TestPlanClientMrpackFilesEnvBeforeDup(t *testing.T) {
	// 服务器专用文件即使与客户端文件同路径，也计入 SkippedEnv（env 判定优先）。
	files := []ModrinthModpackFile{
		envFile("mods/a.jar", "unsupported"),
		envFile("mods/a.jar", "required"),
	}
	sel := planClientMrpackFiles(files)
	if !reflect.DeepEqual(sel.Kept, []int{1}) {
		t.Fatalf("Kept=%v want [1]", sel.Kept)
	}
	if !reflect.DeepEqual(sel.SkippedEnv, []int{0}) {
		t.Fatalf("SkippedEnv=%v want [0]", sel.SkippedEnv)
	}
	if len(sel.SkippedDup) != 0 {
		t.Fatalf("第二个才被保留，不应再判重复: %v", sel.SkippedDup)
	}
}

func TestPlanClientMrpackFilesEmpty(t *testing.T) {
	sel := planClientMrpackFiles(nil)
	if sel.Count() != 0 || len(sel.SkippedEnv) != 0 || len(sel.SkippedDup) != 0 {
		t.Fatalf("空清单应全空，实际 %+v", sel)
	}
}

func TestPlanClientMrpackFilesOrderStable(t *testing.T) {
	files := []ModrinthModpackFile{
		envFile("z.jar", "optional"),
		envFile("s.jar", "unsupported"),
		envFile("a.jar", "required"),
		envFile("m.jar", "required"),
	}
	sel := planClientMrpackFiles(files)
	// 必须严格保持清单中的相对顺序，不做排序。
	if !reflect.DeepEqual(sel.Kept, []int{0, 2, 3}) {
		t.Fatalf("顺序被打乱: %v", sel.Kept)
	}
}

// validateMrpackManifest 应把 env 的非法键 / 非法取值清掉，仅留规范化的 client/server。
func TestValidateMrpackManifestCleansEnv(t *testing.T) {
	m := &ModrinthModpackManifest{
		FormatVersion: 1,
		Game:          "minecraft",
		Name:          "p",
		Dependencies:  map[string]string{"minecraft": "1.20.1"},
		Files: []ModrinthModpackFile{
			{
				Path:      "mods/a.jar",
				Downloads: []string{"https://x.example/a"},
				Env: map[string]string{
					"client":  "REQUIRED",
					"server":  "weird",
					"custom":  "x",
				},
			},
		},
	}
	if err := validateMrpackManifest(m); err != nil {
		t.Fatalf("合法清单不应报错: %v", err)
	}
	env := m.Files[0].Env
	if env["client"] != mrpackEnvRequired {
		t.Fatalf("client 应归一化为 required，实际 %q", env["client"])
	}
	if _, present := env["server"]; present {
		t.Fatal("非法取值 server=weird 应被移除")
	}
	if _, present := env["custom"]; present {
		t.Fatal("未知键 custom 应被移除")
	}
}
