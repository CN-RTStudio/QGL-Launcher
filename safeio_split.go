package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func secureWritePrivateFile(path string, data []byte) error {
	return secureWriteFile(path, data, privateFilePerm)
}

// defaultPrivateJSONWriteMaxBytes 是私有 JSON 写入的默认体量上限，取 64MiB 这种极宽值：
// 只拦截序列化结果被撑到炸磁盘量级的异常配置，正常令牌 / 版本 JSON 是 KB 量级，碰不到。
var defaultPrivateJSONWriteMaxBytes int64 = 64 << 20

// writePrivateJSON 把任意结构序列化为缩进 JSON，再走原子私有写（使用 64MiB 默认上限）。
func writePrivateJSON(path string, v interface{}) error {
	return writePrivateJSONBounded(path, v, 0)
}

// writePrivateJSONBounded 把结构序列化为缩进 JSON，先核实体量再走 0600 原子私有写。
// maxBytes<=0 时取默认 64MiB；空结果、超上限、序列化失败都不落盘并返回错误（超限可用
// errors.Is 识别为 errLocalFileTooLarge），避免吞掉 Marshal/WriteFile 错误后留下半截或巨型文件。
func writePrivateJSONBounded(path string, v interface{}, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = defaultPrivateJSONWriteMaxBytes
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("序列化 JSON 为空，拒绝写入 %s", path)
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("%w: %s 序列化后 %d 字节超过上限 %d", errLocalFileTooLarge, path, len(data), maxBytes)
	}
	return secureWritePrivateFile(path, data)
}

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
