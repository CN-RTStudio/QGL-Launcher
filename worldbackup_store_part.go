package main

import (
	"encoding/json"
	"path/filepath"
)

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
