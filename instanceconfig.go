package main

// instanceconfig：实例配置守卫。
//
// 场景：每个实例目录都有 instance.json（名称/版本/javaPath/mcDir）与
// options.txt（键值配置）。篡改过的实例配置可让启动器：把 javaPath 指向
// 攻击者 exe、把名称塞进 UI（XSS/日志注入）、options.txt 带 CRLF 污染其他
// 输出。本模块：
//   - options.txt：大小/行数/单行长度有界，键值格式校验（key 字符集白名单），
//     拒绝控制字符与裸 CRLF 注入；
//   - instance.json：有界 JSON 解析，字符串字段净化（控制字符剔除、长度
//     截断），javaPath 与 mcDir 路径校验（无穿越/无控制字符）；
//   - 纯函数，不改文件。

import (
	"encoding/json"
	"strings"
)

// InstanceCfgLimits 实例配置守卫的量化边界。
type InstanceCfgLimits struct {
	MaxOptionsBytes int
	MaxOptionLines  int
	MaxOptionLen    int
	MaxJSONBytes    int
	MaxNameRunes    int
	MaxPathLen      int
}

func defaultInstanceCfgLimits() InstanceCfgLimits {
	return InstanceCfgLimits{
		MaxOptionsBytes: 1 << 20,
		MaxOptionLines:  50000,
		MaxOptionLen:    4096,
		MaxJSONBytes:    4 << 20,
		MaxNameRunes:    128,
		MaxPathLen:      2048,
	}
}

type optionLine struct {
	Key   string
	Value string
}

type instanceDoc struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Java    string `json:"javaPath"`
	McDir   string `json:"mcDir"`
}

type instanceVerdict struct {
	OK     bool
	Reason string
	Lines  []optionLine // options.txt 净化后行
	Doc    instanceDoc  // instance.json 净化后字段
}

// sanitizeInstanceText 剔除控制字符并截断 rune。
func sanitizeInstanceText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 && r != '\t' {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return b.String()
}

// keyCharsOK options.txt 键字符集：字母数字下划线点号短横。
func keyCharsOK(key string) bool {
	for _, c := range key {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// ParseOptionsFile 解析 options.txt 内容（按行，键=值）。
func ParseOptionsFile(raw []byte, lim InstanceCfgLimits) instanceVerdict {
	if lim.MaxOptionsBytes == 0 {
		lim = defaultInstanceCfgLimits()
	}
	vd := instanceVerdict{OK: true}
	if len(raw) > lim.MaxOptionsBytes {
		vd.OK = false
		vd.Reason = "options-too-large"
		return vd
	}
	if strings.Contains(string(raw), "\x00") {
		vd.OK = false
		vd.Reason = "options-nul"
		return vd
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > lim.MaxOptionLines {
		vd.OK = false
		vd.Reason = "options-lines-overflow"
		return vd
	}
	clean := []optionLine{}
	for i, ln := range lines {
		ln = strings.TrimSuffix(ln, "\r")
		if len(ln) > lim.MaxOptionLen {
			vd.OK = false
			vd.Reason = "options-line-too-long:" + itoaSafe(i)
			return vd
		}
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		eq := strings.Index(ln, "=")
		if eq <= 0 {
			vd.OK = false
			vd.Reason = "options-no-eq:" + itoaSafe(i)
			return vd
		}
		key := ln[:eq]
		val := ln[eq+1:]
		if !keyCharsOK(key) {
			vd.OK = false
			vd.Reason = "options-key-illegal:" + key
			return vd
		}
		val = sanitizeInstanceText(val, lim.MaxOptionLen)
		clean = append(clean, optionLine{Key: key, Value: val})
	}
	vd.Lines = clean
	return vd
}

// ParseInstanceJSON 解析 instance.json 并净化字段。
func ParseInstanceJSON(raw []byte, lim InstanceCfgLimits) instanceVerdict {
	if lim.MaxJSONBytes == 0 {
		lim = defaultInstanceCfgLimits()
	}
	vd := instanceVerdict{OK: true}
	if len(raw) > lim.MaxJSONBytes {
		vd.OK = false
		vd.Reason = "json-too-large"
		return vd
	}
	var doc instanceDoc
	if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&doc); err != nil {
		vd.OK = false
		vd.Reason = "json-parse-fail"
		return vd
	}
	doc.Name = sanitizeInstanceText(doc.Name, lim.MaxNameRunes)
	doc.Version = sanitizeInstanceText(doc.Version, lim.MaxNameRunes)
	if doc.Java != "" {
		if r := validateLaunchDir(doc.Java); r != "" {
			vd.OK = false
			vd.Reason = "java-path:" + r
			return vd
		}
		if len(doc.Java) > lim.MaxPathLen {
			vd.OK = false
			vd.Reason = "java-path-too-long"
			return vd
		}
	}
	if doc.McDir != "" {
		if r := validateLaunchDir(doc.McDir); r != "" {
			vd.OK = false
			vd.Reason = "mc-dir:" + r
			return vd
		}
	}
	vd.Doc = doc
	return vd
}

// SummarizeInstanceVerdict 压成一行。
func SummarizeInstanceVerdict(vd instanceVerdict) string {
	if vd.OK {
		return "instance ok lines=" + itoaSafe(len(vd.Lines)) + " name=" + vd.Doc.Name
	}
	return "instance bad " + vd.Reason
}
