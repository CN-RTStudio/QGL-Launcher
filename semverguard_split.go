package main

//

import (
	"strconv"
	"strings"
)

func ParseMinecraftVersion(versionID string) (MCSemVersion, bool) {
	if versionID == "" || len(versionID) > maxMCVersionIDLen {
		return MCSemVersion{Kind: mcVersionUnknown}, false
	}
	for i := 0; i < len(versionID); i++ {
		c := versionID[i]
		if c <= 0x20 || c == 0x7f {
			return MCSemVersion{Kind: mcVersionUnknown}, false
		}
	}

	// 快照不含 '-'，优先独立判断。
	if m := reSnapshot.FindStringSubmatch(versionID); m != nil {
		year, _ := strconv.Atoi(m[1])
		week, _ := strconv.Atoi(m[2])
		if week < 1 || week > 53 {
			return MCSemVersion{Kind: mcVersionUnknown}, false
		}
		return MCSemVersion{Kind: mcVersionSnapshot, SnapYear: year, SnapWeek: week}, true
	}

	// 预发布：拆出核心与尾巴分别校验。
	if idx := strings.IndexByte(versionID, '-'); idx >= 0 {
		core := versionID[:idx]
		tail := versionID[idx:]
		pm := rePrerelease.FindStringSubmatch(tail)
		if pm == nil {
			return MCSemVersion{Kind: mcVersionUnknown}, false
		}
		major, minor, patch, ok := parseReleaseCore(core)
		if !ok {
			return MCSemVersion{Kind: mcVersionUnknown}, false
		}
		seq, _ := strconv.Atoi(pm[2])
		if seq < 0 || seq > maxMCVersionSegment {
			return MCSemVersion{Kind: mcVersionUnknown}, false
		}
		return MCSemVersion{
			Major: major, Minor: minor, Patch: patch,
			Kind: mcVersionPrerelease, PreSeq: seq,
		}, true
	}

	// 纯发布核心。
	major, minor, patch, ok := parseReleaseCore(versionID)
	if !ok {
		return MCSemVersion{Kind: mcVersionUnknown}, false
	}
	return MCSemVersion{Major: major, Minor: minor, Patch: patch, Kind: mcVersionRelease}, true
}

// stripLoaderSuffix 取版本标识中加载器 / 空格后缀之前的“上游版本核心”部分，
// 例如 "1.20.1-forge-47.2.0" -> "1.20.1"，"1.21 fabric" -> "1.21"。
// 不做截断以外的清洗；是否可解析交给 ParseMinecraftVersion。
func stripLoaderSuffix(versionID string) string {
	if i := strings.IndexAny(versionID, "- "); i >= 0 {
		return versionID[:i]
	}
	return versionID
}

// CompareRelease 按 主.次.修订 比较两个发布版本：a<b 返回 -1，相等 0，a>b 1。
// 仅对 release / prerelease 的数字核心有意义；调用方需确保两者 Kind 可比较。
func CompareRelease(a, b MCSemVersion) int {
	switch {
	case a.Major != b.Major:
		return signInt(a.Major - b.Major)
	case a.Minor != b.Minor:
		return signInt(a.Minor - b.Minor)
	case a.Patch != b.Patch:
		return signInt(a.Patch - b.Patch)
	default:
		return 0
	}
}

// AtLeast 判断发布版本 a 是否 >= (major,minor,patch)。预发布按其数字核心参与比较，
// 快照不参与发布号比较（返回 false，调用方应单独按快照年份/周处理）。
func (v MCSemVersion) AtLeast(major, minor, patch int) bool {
	if v.Kind != mcVersionRelease && v.Kind != mcVersionPrerelease {
		return false
	}
	return CompareRelease(v, MCSemVersion{Major: major, Minor: minor, Patch: patch}) >= 0
}

// signInt 把整数差值归一为 -1/0/1，避免直接返回可能很大的差值。
func signInt(d int) int {
	switch {
	case d < 0:
		return -1
	case d > 0:
		return 1
	default:
		return 0
	}
}
