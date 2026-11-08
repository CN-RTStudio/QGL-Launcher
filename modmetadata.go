package main

// modmetadata：模组元数据守卫。
//
// 场景：Fabric/Forge 模组的 fabric.mod.json 由作者提供，启动器/Mod 列表页
// 会解析它来显示名称、版本与依赖。恶意模组文件可声明：超长名称（UI/日志
// 注入）、非法 id（污染排序与 URL 拼接）、巨量依赖（解析拖垮）、mixin
// 配置路径穿越（Mixin 加载任意配置）。本模块：
//   - fabric.mod.json 有界解析，字段字符集与长度校验；
//   - id：小写字母数字 _ - .，长度有界；
//   - depends / suggests：键数量与版本串长度有界；
//   - mixins 数组：文件名净化（无穿越/反斜杠/控制字符）；
//   - 描述/作者字段控制字符剔除。

import (
	"encoding/json"
	"strings"
)

// ModMetaLimits 模组元数据守卫的量化边界。
type ModMetaLimits struct {
	MaxJSONBytes  int
	MaxIDLen      int
	MaxFieldRunes int
	MaxDeps       int
	MaxMixins     int
}

func defaultModMetaLimits() ModMetaLimits {
	return ModMetaLimits{MaxJSONBytes: 4 << 20, MaxIDLen: 128, MaxFieldRunes: 1024, MaxDeps: 256, MaxMixins: 256}
}

type fabricModDoc struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Authors     []string          `json:"authors"`
	Depends     map[string]string `json:"depends"`
	Suggests    map[string]string `json:"suggests"`
	Mixins      []string          `json:"mixins"`
}

type modMetaVerdict struct {
	OK      bool
	Reason  string
	Doc     fabricModDoc
}

// modIDOK 校验模组 id 字符集。
func modIDOK(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// modFieldSan 净化自由文本字段。
func modFieldSan(s string, lim ModMetaLimits) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 && r != '\t' {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= lim.MaxFieldRunes {
			break
		}
	}
	return b.String()
}

// mixinFileOK 校验 mixin 配置文件名。
func mixinFileOK(name string) string {
	if name == "" {
		return "empty"
	}
	if len(name) > 512 {
		return "too-long"
	}
	if strings.HasPrefix(name, "/") || (len(name) > 1 && name[1] == ':') {
		return "absolute"
	}
	if strings.Contains(name, "\\") {
		return "backslash"
	}
	if strings.Contains(name, "..") {
		return "dotdot"
	}
	if hasControlCharStr(name) {
		return "control-char"
	}
	return ""
}

// ValidateFabricModMeta 校验 fabric.mod.json。
func ValidateFabricModMeta(raw []byte, lim ModMetaLimits) modMetaVerdict {
	if lim.MaxJSONBytes == 0 {
		lim = defaultModMetaLimits()
	}
	vd := modMetaVerdict{OK: true}
	if len(raw) > lim.MaxJSONBytes {
		vd.OK = false
		vd.Reason = "json-too-large"
		return vd
	}
	var doc fabricModDoc
	if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&doc); err != nil {
		vd.OK = false
		vd.Reason = "parse-fail"
		return vd
	}
	if !modIDOK(doc.ID) {
		vd.OK = false
		vd.Reason = "id-illegal"
		return vd
	}
	doc.Version = modFieldSan(doc.Version, lim)
	if len(doc.Version) > 128 {
		vd.OK = false
		vd.Reason = "version-too-long"
		return vd
	}
	doc.Name = modFieldSan(doc.Name, lim)
	doc.Description = modFieldSan(doc.Description, lim)
	for i := range doc.Authors {
		doc.Authors[i] = modFieldSan(doc.Authors[i], lim)
	}
	for depName, depVer := range doc.Depends {
		if len(doc.Depends) > lim.MaxDeps {
			vd.OK = false
			vd.Reason = "deps-overflow"
			return vd
		}
		if !modIDOK(depName) {
			vd.OK = false
			vd.Reason = "dep-id-illegal:" + depName
			return vd
		}
		if len(depVer) > 128 {
			vd.OK = false
			vd.Reason = "dep-version-too-long"
			return vd
		}
	}
	for name, ver := range doc.Suggests {
		if len(doc.Suggests) > lim.MaxDeps {
			vd.OK = false
			vd.Reason = "suggests-overflow"
			return vd
		}
		if !modIDOK(name) {
			vd.OK = false
			vd.Reason = "suggest-id-illegal"
			return vd
		}
		if len(ver) > 128 {
			vd.OK = false
			vd.Reason = "suggest-version-too-long"
			return vd
		}
	}
	if len(doc.Mixins) > lim.MaxMixins {
		vd.OK = false
		vd.Reason = "mixins-overflow"
		return vd
	}
	for _, m := range doc.Mixins {
		if r := mixinFileOK(m); r != "" {
			vd.OK = false
			vd.Reason = "mixin:" + r
			return vd
		}
	}
	vd.Doc = doc
	return vd
}

// SummarizeModMetaVerdict 压成一行。
func SummarizeModMetaVerdict(vd modMetaVerdict) string {
	if vd.OK {
		return "modmeta ok id=" + vd.Doc.ID + " deps=" + itoaSafe(len(vd.Doc.Depends))
	}
	return "modmeta bad " + vd.Reason
}
