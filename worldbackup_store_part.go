package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// readWorldBackupMeta 读取并核对某备份目录内、指定时间戳的清单与 zip 归属。
func readWorldBackupMeta(dir, worldName, stamp string) (*WorldBackupMeta, string, error) {
	if !validateWorldStamp(stamp) {
		return nil, "", worldError("时间戳不合法")
	}
	zipPath := filepath.Join(dir, stamp+".zip")
	metaPath := zipPathToManifestPath(zipPath)
	if !PathWithinRoot(zipPath, dir) || !PathWithinRoot(metaPath, dir) {
		return nil, "", worldError("备份路径越界")
	}
	if bad, _ := isSymlinkOrSpecial(zipPath); bad {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份 zip 是符号链接或特殊文件，拒绝: "+stamp)
		return nil, "", worldError("拒绝读取链接形式的备份文件")
	}
	const maxManifestBytes = int64(1) << 20
	raw, err := readBoundedFile(metaPath, auditTextReadMaxBytes)
	if err != nil {
		return nil, "", worldError("备份清单不存在或不可读")
	}
	if int64(len(raw)) > maxManifestBytes {
		return nil, "", worldError("备份清单超过大小上限")
	}
	var meta WorldBackupMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, "", worldError("解析备份清单失败")
	}
	if meta.WorldName != worldName || meta.ZipName != filepath.Base(zipPath) {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份清单与文件名/世界归属不一致: "+stamp)
		return nil, "", worldError("备份清单归属校验失败")
	}
	return &meta, zipPath, nil
}

// listWorldBackups 列出某世界现存备份（按时间戳从新到旧）。缺失 / 损坏清单不致命，
// 用 zip 文件本身兜底列出条目，避免一个坏清单导致整个恢复入口不可用。
func listWorldBackups(backupRoot, worldName string) ([]WorldBackupMeta, error) {
	dir, err := worldBackupDirFor(backupRoot, worldName)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []WorldBackupMeta{}, nil
		}
		return nil, err
	}
	out := make([]WorldBackupMeta, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		stamp := strings.TrimSuffix(e.Name(), ".zip")
		if !validateWorldStamp(stamp) {
			continue
		}
		if bad, _ := isSymlinkOrSpecial(filepath.Join(dir, e.Name())); bad {
			continue
		}
		if meta, _, mErr := readWorldBackupMeta(dir, worldName, stamp); mErr == nil {
			out = append(out, *meta)
		} else {
			info, _ := e.Info()
			fallback := WorldBackupMeta{WorldName: worldName, Stamp: stamp, ZipName: e.Name()}
			if info != nil {
				fallback.CreatedAt = info.ModTime().UTC().Format(time.RFC3339)
			}
			out = append(out, fallback)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stamp > out[j].Stamp })
	return out, nil
}
