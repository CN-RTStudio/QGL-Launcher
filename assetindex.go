package main

// assetindex：assets/indexes/<version>.json 守卫。
//
// 场景：Mojang 的 assets 索引把对象名映射到 {hash,size}，启动器按 hash 拼
// 对象路径（objects/<前2位>/<hash>）。篡改的索引可以：把 hash 指向任意文件
// 名（路径穿越）、塞超大对象清单拖垮解析、伪造 size 让下载预算被绕过。
// 本模块：
//   - 有界 JSON 解析 + objects 对象数量上限；
//   - 对象名净化（禁绝对路径/.. 段/控制字符，限长）；
//   - hash 必须 40 位小写十六进制（Mojang 官方 SHA-1 格式，保持原算法，
//     不重算、不换算法）；
//   - size 必须有界（0..MaxObjectSize）；totalSize 有界；
//   - 纯函数，不改文件。

import (
	"encoding/json"
	"strings"
)

// AssetIndexLimits assets 索引守卫的量化边界。
type AssetIndexLimits struct {
	MaxJSONBytes   int
	MaxObjects     int
	MaxNameLen     int
	MaxObjectSize  int64
	MaxTotalSize   int64
}

func defaultAssetIndexLimits() AssetIndexLimits {
	return AssetIndexLimits{
		MaxJSONBytes:  64 << 20,
		MaxObjects:    400000,
		MaxNameLen:    512,
		MaxObjectSize: 1 << 30,
		MaxTotalSize:  64 << 30,
	}
}

type assetEntry struct {
	Name string
	Hash string
	Size int64
}

type assetIndexDoc struct {
	Objects    []assetEntry
	TotalSize  int64
	MapToResources bool
}

type assetIndexVerdict struct {
	OK     bool
	Reason string
	Doc    assetIndexDoc
}

// sha1HexOK Mojang asset hash 是 40 位小写十六进制（官方格式，保持原算法）。
func sha1HexOK(h string) bool {
	if len(h) != 40 {
		return false
	}
	for _, c := range h {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !ok {
			return false
		}
	}
	return true
}

// assetNameOK 对象名必须是相对路径：无盘符/无绝对前缀/无 .. 段/无控制字符。
func assetNameOK(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return false
	}
	if len(name) >= 2 && name[1] == ':' {
		return false
	}
	if strings.ContainsAny(name, "\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

// pathCleanSlash 按 / 清理路径段（不引入 os 依赖，纯字符串处理）。
func pathCleanSlash(p string) string {
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}

// ParseAssetIndex 解析 assets 索引并净化。
func ParseAssetIndex(raw []byte, lim AssetIndexLimits) assetIndexVerdict {
	if lim.MaxJSONBytes == 0 {
		lim = defaultAssetIndexLimits()
	}
	vd := assetIndexVerdict{OK: true}
	if len(raw) > lim.MaxJSONBytes {
		vd.OK = false
		vd.Reason = "json-too-large"
		return vd
	}
	var root struct {
		Objects map[string]struct {
			Hash string `json:"hash"`
			Size int64  `json:"size"`
		} `json:"objects"`
		TotalSize       int64 `json:"totalSize"`
		MapToResources  bool  `json:"map_to_resources"`
	}
	if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&root); err != nil {
		vd.OK = false
		vd.Reason = "json-parse-fail"
		return vd
	}
	if len(root.Objects) > lim.MaxObjects {
		vd.OK = false
		vd.Reason = "objects-overflow"
		return vd
	}
	names := make([]string, 0, len(root.Objects))
	for name := range root.Objects {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		obj := root.Objects[name]
		if !assetNameOK(name) || len(name) > lim.MaxNameLen {
			vd.OK = false
			vd.Reason = "asset-name-illegal"
			return vd
		}
		if !sha1HexOK(obj.Hash) {
			vd.OK = false
			vd.Reason = "asset-hash-format"
			return vd
		}
		if obj.Size < 0 || obj.Size > lim.MaxObjectSize {
			vd.OK = false
			vd.Reason = "asset-size-out-of-range"
			return vd
		}
		vd.Doc.Objects = append(vd.Doc.Objects, assetEntry{Name: name, Hash: obj.Hash, Size: obj.Size})
	}
	vd.Doc.TotalSize = root.TotalSize
	vd.Doc.MapToResources = root.MapToResources
	if root.TotalSize < 0 || root.TotalSize > lim.MaxTotalSize {
		vd.OK = false
		vd.Reason = "total-size-out-of-range"
		return vd
	}
	return vd
}

// SummarizeAssetIndexVerdict 压成一行。
func SummarizeAssetIndexVerdict(vd assetIndexVerdict) string {
	if vd.OK {
		return "assets ok count=" + itoaSafe(len(vd.Doc.Objects)) + " total=" + itoaSafe64(vd.Doc.TotalSize)
	}
	return "assets bad " + vd.Reason
}
