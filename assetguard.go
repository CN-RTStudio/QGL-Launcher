package main

// assetguard.go —— 资产索引（assets indexes / objects）不可信输入收口内核。
//
// 威胁模型：
//   assets/indexes/<id>.json 来自 Mojang / BMCLAPI 镜像，其 objects 表的 key（资源相对
//   路径）与 value.hash / value.size 全部是不可信网络输入。历史代码里存在两处缺口：
//
//   1. 主下载循环（DownloadVersion 内联遍历）虽然校验了 hash 必须是 40 位小写十六进制，
//      但“补全缺失资源”的 fixMissingAssets 只判断 hash != "" 就直接：
//          objPath := filepath.Join(objectsDir, obj.Hash[:2], obj.Hash)
//      于是：
//        - hash 长度 < 2 时 obj.Hash[:2] 越界，整个启动器 goroutine panic（远程 DoS）；
//        - hash 形如 "ab/../../../xxx" 之类时，拼出的路径会跳出 assets/objects 目录，
//          downloadFromMirrors 会把攻击者镜像返回的字节写到 objects 目录之外（路径穿越写）。
//   2. 对象 key（name，例如 minecraft/lang/zh_cn.json）被原样拼进下载 URL，畸形 key（含
//      ".."、反斜杠、控制字符、绝对路径）可改变实际请求路径；索引也没有对象条数上限，
//      一份伪造索引可声明上百万个对象，把遍历 / 下载调度 / 内存拖垮（资源耗尽）。
//
// 本内核把“一个对象能不能被信任地映射到 objects/xx/<40hex>”收敛成纯函数，主下载循环与
// 补全路径统一调用：哈希严格 40 位小写 hex（外部 Mojang 锚，保持 SHA-1 原算法）、对象名
// 做相对路径规范化与段校验、目标路径必须仍落在 objects 目录内、索引条数受上限约束。
// 纯函数不触碰网络 / 文件系统，便于单元测试。

import (
	"path/filepath"
	"strings"
)

const (
	// maxAssetIndexObjects 单份资产索引允许声明的对象条数上限。
	// 真实存量索引约数万条；取 200000 足够覆盖，同时挡住“百万对象”内存 / 调度耗尽。
	// 这是遍历调度的内存闸，不是磁盘容量闸，不限制单个资源文件大小（另有 maxAssetObjectBytes）。
	maxAssetIndexObjects = 200000
	// maxAssetObjectNameLen 单个资源相对路径（objects 的 key）长度上限。
	maxAssetObjectNameLen = 512
	// maxAssetObjectSizeDecl 索引里声明的 size 字段上限，必须与实际落盘上限一致量级。
	maxAssetObjectSizeDecl = maxAssetObjectBytes
)

// 资产对象名拒绝原因码。
const (
	aoOK           = ""
	aoRejectEmpty  = "asset-name-empty"
	aoRejectLen    = "asset-name-too-long"
	aoRejectAbs    = "asset-name-absolute"
	aoRejectDrive  = "asset-name-drive"
	aoRejectBack   = "asset-name-backslash"
	aoRejectCtrl   = "asset-name-control"
	aoRejectSeg    = "asset-name-bad-segment"
	aoRejectTrail  = "asset-name-traversal"
	aoHashBad      = "asset-hash-bad"
	aoSizeBad      = "asset-size-bad"
	aoIndexTooMany = "asset-index-too-many-objects"
)

// isAssetNameSegmentOK 校验资源相对路径中的单段：非空、不是 "." / ".."、不含控制字符。
func isAssetNameSegmentOK(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	for _, c := range seg {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

// validateAssetObjectName 校验 objects 表的 key（资源相对路径）。
// 返回规范化后的相对路径（统一用 "/"，不去重前导斜杠）与是否合法。
func validateAssetObjectName(name string) (string, string) {
	if name == "" {
		return "", aoRejectEmpty
	}
	if len(name) > maxAssetObjectNameLen {
		return "", aoRejectLen
	}
	// 拒绝 Windows 盘符 / UNC 与反斜杠：资源名永远是正斜杠相对路径。
	if strings.Contains(name, "\\") {
		return "", aoRejectBack
	}
	if strings.HasPrefix(name, "/") {
		return "", aoRejectAbs
	}
	// 拒绝任何 ".." 段（正斜杠 / 反斜杠 / 混合都算）。
	// 注意：不能只依赖 filepath.Clean——Windows 上 Clean 会把 "a/../b" 折叠成 "b"，
	// 使穿越探测被静默吞掉；这里必须在规范化前看原始输入。
	if containsDotDotSegment(name) {
		return "", aoRejectTrail
	}
	if hasWindowsDrivePrefix(name) {
		return "", aoRejectDrive
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return "", aoRejectCtrl
		}
	}
	// 用 ToSlash + Clean 规范化后必须仍是多段相对路径且不包含 ".." 段。
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.FromSlash(name))), "./")
	if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", aoRejectTrail
	}
	for _, seg := range strings.Split(clean, "/") {
		if !isAssetNameSegmentOK(seg) {
			return "", aoRejectSeg
		}
	}
	return clean, aoOK
}

// hasWindowsDrivePrefix 判断字符串是否以 X: 形式的盘符开头（如 C:foo）。
func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 {
		return false
	}
	c := p[0]
	driveLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	return driveLetter && p[1] == ':'
}

// containsDotDotSegment 在原始输入上（不 Clean）检测是否存在 ".." 路径段。
// 正斜杠、反斜杠、混合分隔都要命中；空段（"a//b"）不作为独立段。
func containsDotDotSegment(p string) bool {
	if p == ".." {
		return true
	}
	runes := []rune(p)
	segStart := 0
	for i := 0; i <= len(runes); i++ {
		if i == len(runes) || runes[i] == '/' || runes[i] == '\\' {
			if i > segStart {
				seg := string(runes[segStart:i])
				if seg == ".." {
					return true
				}
			}
			segStart = i + 1
		}
	}
	return false
}

// validateAssetObjectHash 资源对象哈希必须是 40 位小写十六进制（SHA-1）。
// 这是 Mojang 外部信任锚，保持原 SHA-1 算法，不替换为本地 UMFS。
func validateAssetObjectHash(hash string) bool {
	return IsLowerHex(hash, 40)
}

// validateAssetObjectSize 校验索引声明的字节数：非负且不超过单对象上限。
func validateAssetObjectSize(size int64) bool {
	return size >= 0 && size <= maxAssetObjectSizeDecl
}

// planAssetObjectDest 把一个已通过哈希校验的对象映射到 objects 目录下的
// "<objectsDir>/<hh>/<40hex>" 目标，并用 PathWithin 复核结果没有越出 objects 目录。
// 返回子目录名、完整目标路径与是否安全。
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

// auditAssetObjects 遍历一份资产索引的 objects 表，把合法对象收集出来，
// 同时统计各类拒绝条数。对象条数超过上限直接返回 aoIndexTooMany。
// 输出顺序按 map 遍历不确定，调用方不应依赖顺序。
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

// describeAssetReject 把资产对象拒绝原因码转成中文说明。
func describeAssetReject(why string) string {
	switch why {
	case aoRejectEmpty:
		return "资源名为空"
	case aoRejectLen:
		return "资源相对路径超过长度上限"
	case aoRejectAbs:
		return "资源名不允许是绝对路径"
	case aoRejectDrive:
		return "资源名不允许包含盘符"
	case aoRejectBack:
		return "资源名不允许包含反斜杠"
	case aoRejectCtrl:
		return "资源名包含控制字符"
	case aoRejectSeg:
		return "资源名包含非法路径段"
	case aoRejectTrail:
		return "资源名存在目录穿越"
	case aoHashBad:
		return "资源哈希不是 40 位小写十六进制"
	case aoSizeBad:
		return "资源声明大小非法"
	case aoIndexTooMany:
		return "资产索引声明的对象条数超过上限"
	default:
		return "资源对象未通过校验"
	}
}
