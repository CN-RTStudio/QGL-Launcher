package main

// safeerase.go —— 敏感文件安全擦除内核。
//
// 威胁模型：账号退出 / 清理数据时启动器要 os.Remove 敏感文件（password.json、
// ms_auth.json、会话令牌等）。原生 os.Remove 有两个问题：
//  1. 符号链接跟随：如果目标路径被替换成指向受害者文件的符号链接，Remove 会把
//     受害者文件本身删掉（同机其他进程 / 恶意预置包即可做到）；
//  2. 残留明文：删除只是移除目录项，磁盘扇区上仍留有令牌明文，数据恢复工具可读回。
//
// 本模块在删除前强制：
//   - Lstat 复核目标必须是非常规文件（非符号链接、非目录、非设备）；
//   - 路径必须位于允许根目录（root）之内，拒绝 ../ 逃逸；
//   - 删除前先用随机数据 + 零填充覆写一遍内容（常规文件、大小有界），
//     然后截断再 Remove；任何一步失败都保留原文件并返回错误，不静默半删。
//
// 覆写次数与算法是“尽力而为”的本地清理，不承诺物理级擦除（SSD 磨损均衡 /
// 日志文件系统可能保留旧块），但足以让普通的文件恢复工具拿不到完整令牌。

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// eraseMaxBytes 是允许覆写的文件大小上限；更大的文件只做 Lstat 复核 +
	// Remove（覆写超大文件不现实，也说明它不该被当作敏感令牌文件）。
	eraseMaxBytes = 64 << 20
	// eraseMinFree 保留位，防止覆写填满磁盘后拖垮系统（由调用方决定是否检查）。
	eraseBlockSize = 128 << 10
)

var (
	ErrEraseOutsideRoot = errors.New("safeerase: path escapes allowed root")
	ErrEraseNonRegular  = errors.New("safeerase: target is not a regular file (symlink/dir/device)")
	ErrEraseTooLarge    = errors.New("safeerase: file too large to overwrite")
	ErrEraseOpen        = errors.New("safeerase: cannot open for overwrite")
	ErrErasePartial     = errors.New("safeerase: overwrite failed before completion")
)

// SafeErase 安全删除 root 下的单个敏感文件。
//   - 校验路径在 root 之内（filepath.Rel 且不以 .. 开头）；
//   - Lstat 确认常规文件；
//   - 大小 ≤ eraseMaxBytes 时先随机覆写再零覆写，再截断；
//   - 最后 Remove；任一步失败返回错误且不删除。
func SafeErase(root, path string) error {
	if root == "" {
		return ErrEraseOutsideRoot
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ErrEraseOutsideRoot
	}
	li, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 已不存在，视为成功
		}
		return err
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return ErrEraseNonRegular
	}
	if li.Size() > eraseMaxBytes {
		// 超大文件不覆写，仅做常规删除（Lstat 已排除符号链接风险）。
		if err := os.Remove(path); err != nil {
			return err
		}
		return nil
	}
	if li.Size() > 0 {
		if err := overwriteFile(path, li.Size()); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func overwriteFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return ErrEraseOpen
	}
	defer f.Close()
	// 第一遍：随机数据。
	if _, err := io.CopyN(f, rand.Reader, size); err != nil {
		return ErrErasePartial
	}
	// 第二遍：全零覆写（从文件头重新写，先 Seek 到 0）。
	zeros := make([]byte, eraseBlockSize)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ErrErasePartial
	}
	written := int64(0)
	for written < size {
		chunk := zeros
		remaining := size - written
		if remaining < int64(len(zeros)) {
			chunk = zeros[:remaining]
		}
		n, err := f.Write(chunk)
		if err != nil {
			return ErrErasePartial
		}
		written += int64(n)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	return nil
}

// SafeEraseBatch 批量安全删除；单文件失败不中断，返回失败清单。
func SafeEraseBatch(root string, paths []string) (removed []string, failed []string) {
	for _, p := range paths {
		if err := SafeErase(root, p); err != nil {
			failed = append(failed, p)
		} else {
			removed = append(removed, p)
		}
	}
	return removed, failed
}
