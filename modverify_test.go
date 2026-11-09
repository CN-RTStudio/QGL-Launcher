package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestModHostAllowed(t *testing.T) {
	allowed := []string{
		"cdn.modrinth.com",
		"api.modrinth.com",
		"edge.forgecdn.net",
		"mediafilez.forgecdn.net",
		"mod.mcimirror.top",
		"CDN.Modrinth.com", // 大小写归一
	}
	for _, h := range allowed {
		if !modHostAllowed(h) {
			t.Errorf("主机应被放行: %q", h)
		}
	}

	denied := []string{
		"",
		"evil.com",
		"cdn.modrinth.com.evil.com",  // 拼后缀视觉混淆
		"notcdn.modrinth.com.evil.cn",
		"xcdn.modrinth.com",          // 前缀伪造，不是子域
		"modrinth.com",               // 主站不提供文件下载，不放进下载白名单
		"127.0.0.1",
		"localhost",
	}
	for _, h := range denied {
		if modHostAllowed(h) {
			t.Errorf("主机应被拒绝: %q", h)
		}
	}
}

func TestValidateModDownloadURL(t *testing.T) {
	ok := []string{
		"https://cdn.modrinth.com/data/abc/versions/x/fabric-api.jar",
		"https://mod.mcimirror.top/modrinth/data/a.jar",
		"https://edge.forgecdn.net/files/1/2/a.jar",
	}
	for _, u := range ok {
		if err := validateModDownloadURL(u); err != nil {
			t.Errorf("URL 应通过校验 %q: %v", u, err)
		}
	}

	bad := []string{
		"",
		"http://cdn.modrinth.com/a.jar",                         // 非 https
		"https://evil.com/a.jar",                               // 主机不在白名单
		"https://cdn.modrinth.com.evil.com/a.jar",              // 拼后缀
		"https://cdn.modrinth.com:8443/a.jar",                  // 非 443 端口
		"https://user:pass@cdn.modrinth.com/a.jar",             // userinfo
		"javascript:alert(1)",
	}
	for _, u := range bad {
		if err := validateModDownloadURL(u); err == nil {
			t.Errorf("URL 应被拒绝: %q", u)
		}
	}
}

func TestModExpectationStoreRecordLookupDelete(t *testing.T) {
	s := newModExpectationStore()
	const u = "https://cdn.modrinth.com/a.jar"

	if _, _, registered := s.lookup(u); registered {
		t.Fatal("空存储不应命中期望值")
	}

	s.record(u, ModFile{
		Size: 1234,
		SHA1: "ABC",
		Hashes: map[string]string{
			"SHA512": "DEF",
		},
	})

	hashes, size, registered := s.lookup(u)
	if !registered {
		t.Fatal("record 后应命中")
	}
	if size != 1234 {
		t.Errorf("size=%d want 1234", size)
	}
	if hashes["sha512"] != "def" || hashes["sha1"] != "abc" {
		t.Errorf("哈希键值未归一为小写: %#v", hashes)
	}

	// 拿到的必须是副本，外部改写不应污染存储。
	hashes["sha512"] = "tampered"
	again, _, _ := s.lookup(u)
	if again["sha512"] != "def" {
		t.Error("lookup 返回的不是副本，存储被外部改写污染")
	}

	// 空值条目不应登记进哈希表。
	s.record("https://cdn.modrinth.com/empty.jar", ModFile{})
	if _, _, registered := s.lookup("https://cdn.modrinth.com/empty.jar"); registered {
		t.Error("全空 ModFile 不应登记期望值")
	}

	s.delete(u)
	if _, _, registered := s.lookup(u); registered {
		t.Error("delete 后不应再命中")
	}
}

// TestModExpectationStoreConcurrentHammer 在并发 record/lookup/delete 下反复
// 访问存储。配合 `go test -race` 可以直接抓到旧实现裸 map 的 data race；
// 不带 -race 时至少保证高并发下不会 panic 或返回脏结构。
func TestModExpectationStoreConcurrentHammer(t *testing.T) {
	s := newModExpectationStore()
	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				u := "https://cdn.modrinth.com/w.jar"
				if i%2 == 0 {
					s.record(u, ModFile{
						Size:   int64(i),
						SHA1:   "aa",
						Hashes: map[string]string{"sha512": "bb"},
					})
				} else if i%3 == 0 {
					s.delete(u)
				} else {
					_, _, _ = s.lookup(u)
				}
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}

func TestFinalizeDownloadFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	partPath := filepath.Join(dir, "a.jar.part")
	destPath := filepath.Join(dir, "a.jar")
	victim := filepath.Join(t.TempDir(), "outside.txt")

	if err := os.WriteFile(partPath, []byte("downloaded"), 0o600); err != nil {
		t.Fatalf("写 part 失败: %v", err)
	}

	// 把目标路径预置成指向目录外文件的符号链接。
	if err := os.Symlink(victim, destPath); err != nil {
		// Windows 上创建符号链接需要开发者模式/管理员权限，无权限时跳过。
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}

	if err := finalizeDownloadFile(partPath, destPath); err == nil {
		t.Fatal("目标为符号链接时 finalizeDownloadFile 必须拒绝")
	}
	if _, err := os.Stat(victim); err == nil {
		t.Error("符号链接指向的目录外文件不应被创建/写穿")
	}
	if _, err := os.Stat(destPath); err != nil {
		t.Errorf("拒绝后预置的符号链接本身应保留原样: %v", err)
	}
}

func TestOpenSecurePartFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	partPath := filepath.Join(dir, "a.jar.part")
	victim := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(victim, []byte("secret"), 0o600); err != nil {
		t.Fatalf("写受害文件失败: %v", err)
	}
	if err := os.Symlink(victim, partPath); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}

	f, err := openSecurePartFile(partPath)
	if err == nil {
		f.Close()
		t.Fatal("part 为符号链接时 openSecurePartFile 必须拒绝")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("读受害文件失败: %v", err)
	}
	if string(got) != "secret" {
		t.Error("受害文件被改写，发生了符号链接写穿")
	}
}
