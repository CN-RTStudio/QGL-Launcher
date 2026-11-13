package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func secureStreamToFile(src io.Reader, dstPath string, perm os.FileMode, maxBytes int64) (int64, error) {
	dir := filepath.Dir(dstPath)
	if err := ensurePrivateDir(dir); err != nil {
		return 0, err
	}
	if bad, err := isSymlinkOrSpecial(dstPath); err != nil {
		return 0, fmt.Errorf("检查目标路径失败: %w", err)
	} else if bad {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"safeio", "目标路径是符号链接或特殊文件，拒绝写入: "+dstPath)
		return 0, fmt.Errorf("拒绝写入符号链接或非普通文件: %s", dstPath)
	}
	tmp, err := os.CreateTemp(dir, ".safeio-stream-*")
	if err != nil {
		return 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(cause error) (int64, error) {
		tmp.Close()
		os.Remove(tmpName)
		return 0, cause
	}
	written, err := io.Copy(tmp, io.LimitReader(src, maxBytes+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return written, fmt.Errorf("写入临时文件失败: %w", err)
	}
	if written > maxBytes {
		tmp.Close()
		os.Remove(tmpName)
		return written, fmt.Errorf("数据超过 %d 字节上限，已拒绝落盘", maxBytes)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(fmt.Errorf("设置文件权限失败: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("刷新文件到磁盘失败: %w", err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return written, fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, dstPath); err != nil {
		os.Remove(tmpName)
		return written, fmt.Errorf("原子替换失败: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return written, nil
}

// copyFileSecure 用原子写的方式复制一个文件（供需要"先备份再覆盖"的场景使用）。
// 通过 LimitReader+1 的多读技巧可以发现文件在读取过程中仍在增长；调用方也可以
// 先用 src 的 Stat 大小限制读取量。
func copyFileSecure(srcPath, dstPath string, perm os.FileMode, maxBytes int64) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %w", err)
	}
	defer src.Close()
	if bad, err := isSymlinkOrSpecial(srcPath); err != nil {
		return err
	} else if bad {
		return fmt.Errorf("拒绝从符号链接或非普通文件复制: %s", srcPath)
	}
	if _, err := secureStreamToFile(src, dstPath, perm, maxBytes); err != nil {
		return err
	}
	return nil
}

func secureWriteFile(path string, data []byte, perm os.FileMode) (retErr error) {
	if filepath.Clean(path) == "." || filepath.Dir(path) == path {
		return fmt.Errorf("非法的落盘路径: %q", path)
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	if bad, err := isSymlinkOrSpecial(path); err != nil {
		return fmt.Errorf("检查目标路径失败: %w", err)
	} else if bad {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"safeio", "目标路径是符号链接或特殊文件，拒绝写入: "+path)
		return fmt.Errorf("拒绝写入符号链接或非普通文件: %s", path)
	}

	tmp, err := os.CreateTemp(dir, ".safeio-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	// 统一的失败回收路径：关闭 + 删除临时文件。
	defer func() {
		if retErr != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	// 先收敛权限再 Sync，避免数据在权限还是 0600（CreateTemp 默认 0600，
	// 这里显式再设一次以防平台差异）的窗口之外落盘。
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("刷新文件到磁盘失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("原子替换失败: %w", err)
	}
	// 替换后再次确认最终文件权限。Windows 上 Chmod 只影响只读位，属于无害空操作。
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("收敛目标文件权限失败: %w", err)
	}
	// 目录 fsync 失败不影响数据正确性（极端掉电场景才相关），只做尽力而为。
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
