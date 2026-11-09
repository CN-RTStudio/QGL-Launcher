package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// 本文件集中处理"敏感/关键状态文件"的落盘安全。
//
// 背景：OpenQGL 会在 QGL 数据目录写入密码文件（password.json）、微软 / 外置
// 登录令牌（ms_auth.json / external_auth.json）、加密盐、用户与全局配置等。
// 这些文件历史上直接用 os.WriteFile(path, data, 0600) 落盘，存在四个问题：
//
//  1. O_TRUNC 原地覆盖：进程在写到一半时崩溃 / 断电，文件会留下半截 JSON，
//     下一次启动直接解析失败，账号数据"看起来丢了"。
//  2. 跟随符号链接：如果目标路径事先被建成指向其它位置的符号链接（同一台机器
//     上的其它进程 / 用户，或恶意安装包预置），os.WriteFile 会顺着链接把
//     令牌 / 密码改写进链接指向的任意文件。
//  3. 0600 只在"创建新文件"时生效：文件已经以宽松权限存在时，WriteFile 不会
//     把权限收紧。
//  4. 数据只进了页缓存：rename 之后掉电，目录项与数据可能都没真正落盘。
//
// secureWritePrivateFile 用"同目录 O_EXCL 临时文件 -> fsync -> chmod 0600 ->
// rename -> 目录 fsync"的标准原子写流程一次性解决这些问题。

const (
	// privateFilePerm 是敏感文件权限：仅属主可读写。
	privateFilePerm os.FileMode = 0o600
	// privateDirPerm 是敏感目录权限：仅属主可进入。
	privateDirPerm os.FileMode = 0o700
)

// isSymlinkOrSpecial 判断路径是否已经作为符号链接 / 特殊文件存在。
// 普通文件或"不存在"都允许落盘；符号链接一律拒绝，防止写穿（link following）。
func isSymlinkOrSpecial(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	if info.IsDir() {
		return false, nil
	}
	// 命名管道、设备文件、socket 等也不是正常落盘目标。
	if !info.Mode().IsRegular() {
		return true, nil
	}
	return false, nil
}

// ensurePrivateDir 确保目录存在且权限收敛为 0700。
// 目录已存在时同样执行 Chmod，避免历史目录被建成 0755 导致其它用户可进入。
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, privateDirPerm); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	if err := os.Chmod(dir, privateDirPerm); err != nil {
		return fmt.Errorf("收敛目录权限失败: %w", err)
	}
	return nil
}

// secureWriteFile 是原子写内核：
//   - parentDir 不存在时以 0700 创建；
//   - 目标路径已存在且是符号链接 / 特殊文件时直接拒绝；
//   - 在同目录用 O_CREATE|O_EXCL 建唯一临时文件（0600），跨设备 rename 的坑
//     也因此被避开（临时文件与目标必然在同一文件系统）；
//   - 写完 Sync 落盘，再 Chmod 0600，最后 Rename 原子替换；
//   - rename 后对目录做一次 Sync，尽量保证目录项也落盘。
//
// 任意一步失败都会尝试清理临时文件，绝不在数据目录留下带密钥内容的残文件。
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

// secureWritePrivateFile 写入敏感数据（令牌 / 密码 / 盐 / 配置），权限锁死 0600。
