package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func writeWorldZipAtomic(planned []worldPlannedFile, zipPath string, lim WorldBackupLimits) (int, int64, error) {
	dir := filepath.Dir(zipPath)
	if err := ensurePrivateDir(dir); err != nil {
		return 0, 0, err
	}
	tmp, err := os.CreateTemp(dir, ".worldbackup-*")
	if err != nil {
		return 0, 0, fmt.Errorf("创建备份临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	abort := func(cause error) (int, int64, error) {
		tmp.Close()
		os.Remove(tmpName)
		return 0, 0, cause
	}

	zw := zip.NewWriter(tmp)
	var written int64
	for i := range planned {
		f := planned[i]
		in, openErr := os.Open(f.abs)
		if openErr != nil {
			zw.Close()
			return abort(fmt.Errorf("打开世界文件失败 %s: %w", f.rel, openErr))
		}
		header := &zip.FileHeader{Name: f.rel, Method: zip.Deflate}
		header.SetMode(0o600)
		w, createErr := zw.CreateHeader(header)
		if createErr != nil {
			in.Close()
			zw.Close()
			return abort(fmt.Errorf("创建 zip 条目失败 %s: %w", f.rel, createErr))
		}
		// 多读 1 字节：若文件在规划后又被写大，立即中止而不是悄悄截断。
		n, copyErr := io.Copy(w, io.LimitReader(in, f.size+1))
		in.Close()
		if copyErr != nil {
			zw.Close()
			return abort(fmt.Errorf("读取世界文件失败 %s: %w", f.rel, copyErr))
		}
		if n != f.size {
			zw.Close()
			return abort(worldError(fmt.Sprintf("世界文件在备份期间大小变化: %s", f.rel)))
		}
		written += n
		if written > lim.MaxTotalBytes {
			zw.Close()
			return abort(worldError("备份写入总量超过上限"))
		}
	}
	if err := zw.Close(); err != nil {
		return abort(fmt.Errorf("完成 zip 写入失败: %w", err))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return abort(fmt.Errorf("收敛备份权限失败: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return abort(fmt.Errorf("刷新备份到磁盘失败: %w", err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, 0, fmt.Errorf("关闭备份临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, zipPath); err != nil {
		os.Remove(tmpName)
		return 0, 0, fmt.Errorf("备份原子替换失败: %w", err)
	}
	return len(planned), written, nil
}

// umfsFileHex 计算文件的 UMFS 摘要（小写 hex），用于本地备份完整性核对。
func umfsFileHex(path string) (string, error) {
	return umfsFile(path)
}

// worldBackupDirFor 返回某世界的备份目录 root/<world>，并保证名段安全。
func worldBackupDirFor(root, worldName string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	dir := filepath.Join(root, cleanName)
	if !PathWithinRoot(dir, root) {
		return "", worldError("备份目录解析越界")
	}
	return dir, nil
}

// uniqueStampZipPath 在备份目录内为时间戳分配一个不存在的 zip 路径，
// 极端的同一秒连续备份用 -01.. 后缀避让，绝不覆盖既有备份。
func uniqueStampZipPath(dir, stamp string) (string, error) {
	if !validateWorldStamp(stamp) {
		return "", worldError("时间戳不合法")
	}
	candidate := filepath.Join(dir, stamp+".zip")
	for i := 0; i < 100; i++ {
		if i == 0 {
			candidate = filepath.Join(dir, stamp+".zip")
		} else {
			candidate = filepath.Join(dir, fmt.Sprintf("%s-%02d.zip", stamp, i))
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", worldError("同一时间戳备份过多，无法分配文件名")
}

// zipPathToManifestPath 返回与某个 zip 配套的清单路径。
func zipPathToManifestPath(zipPath string) string {
	return strings.TrimSuffix(zipPath, ".zip") + ".json"
}
