package main

// profilejson：launcher_profiles.json 守卫。
//
// 场景：启动器把游戏版本/启动参数/选中用户写进 launcher_profiles.json，
// 篡改过的文件可以把 profile 名称塞进 UI（日志注入/XSS）、把 version
// 指到不存在的目录、或塞进超大对象让启动器内存被打爆。本模块：
//   - 有界 JSON 解析（整体字节上限 + profiles 对象数量上限 + 单字段长度上限）；
//   - profile 名称 / selectedUser 账号 / lastVersionId 字符集净化（剔除
//     控制字符，禁止 CR/LF 注入）；
//   - type 字段只允许已知取值（latest-release/latest-snapshot/自定义名），
//     未知一律净化；path 字段必须为相对路径（禁绝对路径/盘符/.. 穿越）；
//   - 纯函数，不改文件。

import (
	"encoding/json"
	"strings"
)

// ProfileLimits launcher_profiles.json 守卫的量化边界。
type ProfileLimits struct {
	MaxJSONBytes  int
	MaxProfiles   int
	MaxNameRunes  int
	MaxFieldLen   int
	MaxPathLen    int
}

func defaultProfileLimits() ProfileLimits {
	return ProfileLimits{
		MaxJSONBytes: 4 << 20,
		MaxProfiles:  200,
		MaxNameRunes: 64,
		MaxFieldLen:  512,
		MaxPathLen:   2048,
	}
}

type profileEntry struct {
	Name     string
	Version  string
	Type     string
	Path     string
}

type profileDoc struct {
	Profiles      []profileEntry
	SelectedUser  string
	ClientVersion int
}

type profileVerdict struct {
	OK     bool
	Reason string
	Doc    profileDoc
}

// cleanProfileField 剔除控制字符并截断 rune（name/version/account 通用）。
func cleanProfileField(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return b.String()
}

// relativeProfilePathOK 只允许普通相对路径：禁空、禁绝对路径、禁盘符、
// 禁反斜杠（Windows 风格穿越）、禁 . 与 .. 段、禁控制字符。
func relativeProfilePathOK(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return false
	}
	if len(p) >= 2 && p[1] == ':' {
		return false
	}
	if strings.ContainsAny(p, "\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

// profileTypeOK type 字段白名单。
func profileTypeOK(t string) bool {
	switch t {
	case "latest-release", "latest-snapshot", "custom":
		return true
	}
	return t != ""
}

// ParseProfilesJSON 解析 launcher_profiles.json 并净化字段。
func ParseProfilesJSON(raw []byte, lim ProfileLimits) profileVerdict {
	if lim.MaxJSONBytes == 0 {
		lim = defaultProfileLimits()
	}
	vd := profileVerdict{OK: true}
	if len(raw) > lim.MaxJSONBytes {
		vd.OK = false
		vd.Reason = "json-too-large"
		return vd
	}
	var root struct {
		Profiles map[string]struct {
			Name           string `json:"name"`
			LastVersionID  string `json:"lastVersionId"`
			Type           string `json:"type"`
			GameDir        string `json:"gameDir"`
			JavaArgs       string `json:"javaArgs"`
		} `json:"profiles"`
		SelectedUser struct {
			Account string `json:"account"`
			Profile string `json:"profile"`
		} `json:"selectedUser"`
		ClientVersion int `json:"clientVersion"`
	}
	if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&root); err != nil {
		vd.OK = false
		vd.Reason = "json-parse-fail"
		return vd
	}
	if len(root.Profiles) > lim.MaxProfiles {
		vd.OK = false
		vd.Reason = "profiles-overflow"
		return vd
	}
	// map 迭代顺序不稳定，按名字排好序再输出，保证报告确定性。
	names := make([]string, 0, len(root.Profiles))
	for name := range root.Profiles {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		p := root.Profiles[name]
		ent := profileEntry{
			Name:    cleanProfileField(name, lim.MaxNameRunes),
			Version: cleanProfileField(p.LastVersionID, lim.MaxNameRunes),
			Type:    cleanProfileField(p.Type, lim.MaxNameRunes),
		}
		if ent.Name == "" {
			vd.OK = false
			vd.Reason = "profile-name-empty"
			return vd
		}
		if strings.ContainsAny(ent.Name, "\r\n") {
			vd.OK = false
			vd.Reason = "profile-name-crlf"
			return vd
		}
		if !profileTypeOK(ent.Type) {
			ent.Type = "custom"
		}
		if p.GameDir != "" {
			if !relativeProfilePathOK(p.GameDir) || len(p.GameDir) > lim.MaxPathLen {
				vd.OK = false
				vd.Reason = "profile-dir:" + name
				return vd
			}
			ent.Path = p.GameDir
		}
		if len(p.JavaArgs) > lim.MaxFieldLen {
			vd.OK = false
			vd.Reason = "profile-javaargs-too-long:" + name
			return vd
		}
		vd.Doc.Profiles = append(vd.Doc.Profiles, ent)
	}
	vd.Doc.SelectedUser = cleanProfileField(root.SelectedUser.Account, lim.MaxNameRunes)
	vd.Doc.ClientVersion = root.ClientVersion
	if vd.Doc.ClientVersion < 0 || vd.Doc.ClientVersion > 100000 {
		vd.Doc.ClientVersion = 0
	}
	return vd
}

// SummarizeProfileVerdict 压成一行。
func SummarizeProfileVerdict(vd profileVerdict) string {
	if vd.OK {
		return "profiles ok count=" + itoaSafe(len(vd.Doc.Profiles))
	}
	return "profiles bad " + vd.Reason
}
