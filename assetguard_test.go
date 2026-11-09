package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 威胁模型回归：assets 索引来自镜像，hash/name/size 均不可信。
// 这些用例保证短哈希不再触发切片 panic、穿越名不会映射到 objects 目录之外。

func validAssetHash() string {
	return strings.Repeat("a", 40)
}

func TestValidateAssetObjectHash(t *testing.T) {
	cases := []struct {
		name string
		hash string
		want bool
	}{
		{"40 位小写 hex", validAssetHash(), true},
		{"40 位数字 hex", strings.Repeat("9", 40), true},
		{"短哈希（会触发旧版 [:2] panic）", "a", false},
		{"空哈希", "", false},
		{"39 位", strings.Repeat("a", 39), false},
		{"41 位", strings.Repeat("a", 41), false},
		{"含大写", strings.Repeat("A", 40), false},
		{"含穿越点", "ab/.." + strings.Repeat("0", 35), false},
		{"含反斜杠", "ab" + `\..\` + strings.Repeat("0", 35), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validateAssetObjectHash(c.hash); got != c.want {
				t.Fatalf("validateAssetObjectHash(%q) = %v, want %v", c.hash, got, c.want)
			}
		})
	}
}

func TestValidateAssetObjectName(t *testing.T) {
	good := []string{
		"minecraft/lang/zh_cn.json",
		"icons/icon_16x16.png",
		"realms/textures/gui/title/background/panorama_0.png",
		"a/b/c",
	}
	for _, n := range good {
		if _, why := validateAssetObjectName(n); why != aoOK {
			t.Fatalf("期望合法的资源名被拒: %q (%s)", n, why)
		}
	}

	bad := map[string]string{
		"":                              aoRejectEmpty,
		strings.Repeat("x", 600):        aoRejectLen,
		"/etc/passwd":                   aoRejectAbs,
		"minecraft/../../evil":          aoRejectTrail,
		`..\windows\system32`:            aoRejectBack,
		`C:windows\evil`:                 aoRejectBack,
		"minecraft/../evil":             aoRejectTrail,
		"minecraft/lang/\x00.json":      aoRejectCtrl,
		"./minecraft/lang/zh_cn.json":   aoOK, // 前导 ./ 会被 Clean 归一，仍合法
	}
	for name, wantWhy := range bad {
		_, why := validateAssetObjectName(name)
		if wantWhy == aoOK {
			if why != aoOK {
				t.Fatalf("期望 %q 被归一后合法，实际拒绝 %s", name, why)
			}
			continue
		}
		if why != wantWhy {
			t.Fatalf("validateAssetObjectName(%q) = %s, want %s", name, why, wantWhy)
		}
	}
}

func TestValidateAssetObjectSize(t *testing.T) {
	if !validateAssetObjectSize(0) {
		t.Fatal("0 字节对象应允许")
	}
	if !validateAssetObjectSize(maxAssetObjectSizeDecl) {
		t.Fatal("等于上限的声明大小应允许")
	}
	if validateAssetObjectSize(-1) {
		t.Fatal("负数大小必须拒绝")
	}
	if validateAssetObjectSize(maxAssetObjectSizeDecl+1) {
		t.Fatal("超过上限的声明大小必须拒绝")
	}
}

func TestPlanAssetObjectDest(t *testing.T) {
	objectsDir := filepath.Clean("/tmp/mc/assets/objects")
	hash := validAssetHash()
	sub, dest, ok := planAssetObjectDest(objectsDir, hash)
	if !ok {
		t.Fatal("合法哈希应能规划出目标路径")
	}
	if sub != hash[:2] {
		t.Fatalf("子目录 = %q, want %q", sub, hash[:2])
	}
	want := filepath.Join(objectsDir, hash[:2], hash)
	if dest != want {
		t.Fatalf("dest = %q, want %q", dest, want)
	}
	if !PathWithinRoot(dest, objectsDir) {
		t.Fatal("规划出的目标必须在 objects 目录内")
	}
	if _, _, ok := planAssetObjectDest(objectsDir, "ab"); ok {
		t.Fatal("短哈希必须拒绝，且不得 panic")
	}
}

func TestAuditAssetObjectsMixed(t *testing.T) {
	objects := map[string]AssetObject{
		"minecraft/lang/zh_cn.json": {Hash: validAssetHash(), Size: 123},
		"icons/icon_16x16.png":      {Hash: strings.Repeat("b", 40), Size: 456},
		"bad/short":                 {Hash: "ab", Size: 1},          // 短哈希
		"../escape.png":             {Hash: validAssetHash(), Size: 1}, // 穿越名
		"bad/negative":              {Hash: strings.Repeat("c", 40), Size: -2}, // 负大小
	}
	safe, rejects, why := auditAssetObjects(objects)
	if why != aoOK {
		t.Fatalf("未超条数时不应整体拒绝，got %s", why)
	}
	if len(safe) != 2 {
		t.Fatalf("合法对象数 = %d, want 2", len(safe))
	}
	if rejects[aoHashBad] != 1 {
		t.Fatalf("非法哈希计数 = %d, want 1", rejects[aoHashBad])
	}
	if rejects[aoRejectTrail] != 1 {
		t.Fatalf("穿越名计数 = %d, want 1", rejects[aoRejectTrail])
	}
	if rejects[aoSizeBad] != 1 {
		t.Fatalf("非法大小计数 = %d, want 1", rejects[aoSizeBad])
	}
}

func TestAuditAssetObjectsTooMany(t *testing.T) {
	objects := make(map[string]AssetObject, maxAssetIndexObjects+1)
	for i := 0; i < maxAssetIndexObjects+1; i++ {
		// key 带唯一序号，保证互不相同且路径合法（序号在文件名段内）。
		key := "x/obj_" + strconv.Itoa(i) + ".json"
		objects[key] = AssetObject{Hash: strings.Repeat("a", 40), Size: 1}
	}
	_, _, why := auditAssetObjects(objects)
	if why != aoIndexTooMany {
		t.Fatalf("超条数索引应整体拒绝，got %q", why)
	}
}

func TestDescribeAssetReject(t *testing.T) {
	if got := describeAssetReject(aoHashBad); !strings.Contains(got, "十六进制") {
		t.Fatalf("哈希拒绝说明不含关键信息: %q", got)
	}
	if got := describeAssetReject("unknown-code"); got == "" {
		t.Fatal("未知原因码也应给出兜底说明")
	}
}
