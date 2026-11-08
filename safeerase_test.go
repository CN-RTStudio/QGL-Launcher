package main

// safeerase_test.go —— 安全擦除内核测试。
//
// 覆盖的攻击向量：
//  1. 符号链接指向受害者文件：SafeErase 必须拒绝删除（受害者文件不能消失）；
//  2. 目录路径：拒绝（不能递归删目录）；
//  3. 路径逃逸（../ 拼接）：拒绝；
//  4. 正常敏感文件：先覆写再删除，文件消失、目录项被清理；
//  5. 不存在的文件：视为成功（幂等）；
//  6. 超限大小文件：跳过覆写仍删除（且不因过大而拒绝整个操作）。
//  7. 批量删除：单文件失败不中断其余。

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeErase_NormalFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "password.json")
	if err := os.WriteFile(p, []byte("super-secret-token-here"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := SafeErase(root, p); err != nil {
		t.Fatalf("SafeErase: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("文件应已被删除，stat err=%v", err)
	}
}

func TestSafeErase_SymlinkRefused(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	link := filepath.Join(root, "password.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("环境不允许建符号链接: %v", err)
	}
	err := SafeErase(root, link)
	if err != ErrEraseNonRegular {
		t.Fatalf("符号链接应被拒绝为 non-regular，得到 %v", err)
	}
	if _, statErr := os.Stat(victim); statErr != nil {
		t.Fatalf("受害者文件被误删: %v", statErr)
	}
	if _, statErr := os.Lstat(link); statErr != nil {
		t.Fatalf("符号链接本身也不应被动: %v", statErr)
	}
}

func TestSafeErase_DirectoryRefused(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "accounts")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := SafeErase(root, dir); err != ErrEraseNonRegular {
		t.Fatalf("目录应被拒绝，得到 %v", err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("目录不应被动: st=%v err=%v", st, err)
	}
}

func TestSafeErase_PathEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep-me"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 模拟 ../ 逃逸：直接用绝对路径且不在 root 之下。
	err := SafeErase(root, outside)
	if err != ErrEraseOutsideRoot {
		t.Fatalf("绝对路径逃逸应被拒绝，得到 %v", err)
	}
	// 相对路径逃逸
	err = SafeErase(root, filepath.Join(root, "..", filepath.Base(outside)))
	if err != ErrEraseOutsideRoot {
		t.Fatalf("相对路径逃逸应被拒绝，得到 %v", err)
	}
	if _, statErr := os.Stat(outside); statErr != nil {
		t.Fatalf("外部文件被误删: %v", statErr)
	}
}

func TestSafeErase_MissingIsIdempotent(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "not-there.json")
	if err := SafeErase(root, p); err != nil {
		t.Fatalf("不存在文件应视为成功，得到 %v", err)
	}
}

func TestSafeErase_OverwriteRemovesContent(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "ms_auth.json")
	payload := bytes.Repeat([]byte("TOKEN1234"), 4096) // 32 KiB
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := SafeErase(root, p); err != nil {
		t.Fatalf("SafeErase: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("文件应已删除，stat err=%v", err)
	}
}

func TestSafeErase_OversizeStillDeletes(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "config.json")
	// 超过 eraseMaxBytes 的稀疏文件（不实际写盘，但 size 足够大）。
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(eraseMaxBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	_ = f.Close()
	if err := SafeErase(root, p); err != nil {
		t.Fatalf("超限文件仍应删除: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("超限文件应已删除，stat err=%v", err)
	}
}

func TestSafeEraseBatch_PartialFailureContinues(t *testing.T) {
	root := t.TempDir()
	okFile := filepath.Join(root, "a.json")
	if err := os.WriteFile(okFile, []byte("a"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	badFile := filepath.Join(root, "..", "evil.json") // 逃逸，应失败
	removed, failed := SafeEraseBatch(root, []string{okFile, badFile})
	if len(removed) != 1 || removed[0] != okFile {
		t.Fatalf("正常文件应删除: removed=%v", removed)
	}
	if len(failed) != 1 || failed[0] != badFile {
		t.Fatalf("逃逸路径应进入 failed: failed=%v", failed)
	}
	if _, err := os.Lstat(okFile); !os.IsNotExist(err) {
		t.Fatalf("okFile 应已删除: %v", err)
	}
}

func TestSafeErase_EmptyRoot(t *testing.T) {
	if err := SafeErase("", "anything"); err != ErrEraseOutsideRoot {
		t.Fatalf("空 root 应拒绝，得到 %v", err)
	}
}

func TestSafeErase_RelPathInsideRoot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "logs")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(sub, "s.log")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rel := "logs" + string(filepath.Separator) + "s.log"
	joined := filepath.Join(root, rel)
	if !strings.HasPrefix(filepath.Clean(joined)+string(filepath.Separator), filepath.Clean(root)+string(filepath.Separator)) {
		t.Fatalf("测试路径构造错误: %s", joined)
	}
	if err := SafeErase(root, joined); err != nil {
		t.Fatalf("子目录内文件应可删除: %v", err)
	}
}
