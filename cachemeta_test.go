package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// hashSHA1 / hashSHA512 在测试里独立算一遍期望摘要，不依赖被测函数。
func hashSHA1(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])
}

func hashSHA512Str(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	s := sha512.Sum512(b)
	return hex.EncodeToString(s[:])
}

func writeTempArtifact(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	return p
}

// TestCacheVerifyBackfillsMeta：没有侧车时回退到官方 SHA1，
// 命中后应当自动补写出包含 UMFS / SHA512 的侧车。
func TestCacheVerifyBackfillsMeta(t *testing.T) {
	a := &App{}
	p := writeTempArtifact(t, []byte("openqgl-cache-verify-roundtrip-内容"))
	official := hashSHA1(t, p)

	if !a.verifyCachedFile(p, official) {
		t.Fatal("无侧车时应当用官方 SHA1 命中并回填")
	}
	meta, ok := loadCachedFileMeta(p)
	if !ok {
		t.Fatal("命中后应当写得出侧车元数据")
	}
	if meta.UMFS == "" || meta.SHA512 == "" {
		t.Fatalf("回填的侧车缺少本地摘要 UMFS=%v SHA512=%v", meta.UMFS != "", meta.SHA512 != "")
	}
	if !equalFoldASCII(meta.SHA1, official) {
		t.Fatal("侧车记录的权威 SHA1 与官方值不一致")
	}
}

// TestCacheVerifyTamperNoDowngrade：文件被改动后，即便 UMFS 对不上，
// 也不允许悄悄降级到更弱算法放行，必须判缓存失效。
func TestCacheVerifyTamperNoDowngrade(t *testing.T) {
	a := &App{}
	p := writeTempArtifact(t, []byte("original-bytes"))
	official := hashSHA1(t, p)
	if !a.verifyCachedFile(p, official) {
		t.Fatal("前置：首次应当命中并建立侧车")
	}
	// 篡改文件但保留侧车不动。
	if err := os.WriteFile(p, []byte("tampered-bytes!!!"), 0o600); err != nil {
		t.Fatalf("篡改写入失败: %v", err)
	}
	if a.verifyCachedFile(p, official) {
		t.Fatal("UMFS 比对失败时不应降级放行被篡改的缓存")
	}
}

// TestCacheVerifySHA512OnlyFallback：侧车只有 SHA512（缺 UMFS）时，
// 按 UMFS -> SHA512 -> SHA1 顺序应落到 SHA512 并命中。
func TestCacheVerifySHA512OnlyFallback(t *testing.T) {
	a := &App{}
	p := writeTempArtifact(t, []byte("sha512-only-sidecar"))
	official := hashSHA1(t, p)
	info, _ := os.Stat(p)
	meta := cachedFileMeta{SHA1: official, SHA512: hashSHA512Str(t, p), Size: info.Size()}
	b, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(metaPathFor(p), b, 0o600); err != nil {
		t.Fatalf("写侧车失败: %v", err)
	}
	if !a.verifyCachedFile(p, official) {
		t.Fatal("缺 UMFS 时应当回退到 SHA512 命中")
	}
}

// TestCacheVerifySizeMismatch：尺寸预检对不上应直接判失效，不浪费哈希计算。
func TestCacheVerifySizeMismatch(t *testing.T) {
	a := &App{}
	p := writeTempArtifact(t, []byte("size-check"))
	official := hashSHA1(t, p)
	info, _ := os.Stat(p)
	meta := cachedFileMeta{
		SHA1:   official,
		SHA512: hashSHA512Str(t, p),
		UMFS:   "deadbeef",
		Size:   info.Size() + 999,
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(metaPathFor(p), b, 0o600)
	if a.verifyCachedFile(p, official) {
		t.Fatal("尺寸不一致的缓存不应被判为有效")
	}
}

// TestCacheVerifyOfficialMismatch：侧车绑定的权威 SHA1 与本次期望不同，
// 说明侧车不属于当前对象，必须拒绝。
func TestCacheVerifyOfficialMismatch(t *testing.T) {
	a := &App{}
	p := writeTempArtifact(t, []byte("binding-check"))
	info, _ := os.Stat(p)
	meta := cachedFileMeta{SHA1: "0000000000000000000000000000000000000000", Size: info.Size()}
	b, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(metaPathFor(p), b, 0o600)
	if a.verifyCachedFile(p, hashSHA1(t, p)) {
		t.Fatal("侧车权威 SHA1 与期望不一致时应当拒绝")
	}
}

// TestRemoveCachedFileMeta：删除侧车应当幂等，文件不存在也不报错。
func TestRemoveCachedFileMeta(t *testing.T) {
	p := writeTempArtifact(t, []byte("cleanup"))
	_ = os.WriteFile(metaPathFor(p), []byte("{}"), 0o600)
	removeCachedFileMeta(p)
	if _, err := os.Stat(metaPathFor(p)); !os.IsNotExist(err) {
		t.Fatal("侧车应当已被删除")
	}
	removeCachedFileMeta(p) // 再次删除不应 panic
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
