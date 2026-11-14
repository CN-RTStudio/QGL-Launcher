package main

import (
	"path/filepath"
)

func planAssetObjectDest(objectsDir, hash string) (string, string, bool) {
	if !validateAssetObjectHash(hash) {
		return "", "", false
	}
	sub := hash[:2]
	dest := filepath.Join(objectsDir, sub, hash)
	// hash 已严格限定为 40 位小写 hex，词法上无法逃逸，仍做一次归属判定作为纵深防御。
	if !PathWithinRoot(dest, objectsDir) {
		return "", "", false
	}
	return sub, dest, true
}

// SafeAssetObject 是通过校验、可安全下载 / 落盘的单个资源对象。
type SafeAssetObject struct {
	Name string // 规范化后的资源相对路径（仅用于拼下载 URL 与日志）
	Hash string // 40 位小写十六进制
	Size int64  // 声明字节数
}

func auditAssetObjects(objects map[string]AssetObject) ([]SafeAssetObject, map[string]int, string) {
	if len(objects) > maxAssetIndexObjects {
		return nil, nil, aoIndexTooMany
	}
	safe := make([]SafeAssetObject, 0, len(objects))
	rejects := map[string]int{}
	for name, obj := range objects {
		cleanName, whyName := validateAssetObjectName(name)
		if whyName != aoOK {
			rejects[whyName]++
			continue
		}
		if !validateAssetObjectHash(obj.Hash) {
			rejects[aoHashBad]++
			continue
		}
		if !validateAssetObjectSize(obj.Size) {
			rejects[aoSizeBad]++
			continue
		}
		safe = append(safe, SafeAssetObject{Name: cleanName, Hash: obj.Hash, Size: obj.Size})
	}
	return safe, rejects, aoOK
}

func describeAssetReject(why string) string {
	return rejectReasonText(why, "资源对象未通过校验", describeAssetRejectTexts)
}
