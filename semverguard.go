package main

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	mcVersionUnknown    = "unknown"
	mcVersionRelease    = "release"    // 形如 1.20.4 / 1.21
	mcVersionSnapshot   = "snapshot"   // 形如 24w14a
	mcVersionPrerelease = "prerelease" // 形如 1.21-pre1 / 1.21-rc2
)
const maxMCVersionSegment = 999
const maxMCVersionIDLen = 128

var (
	// 发布核心：1~3 段纯数字点分，例如 "1"、"1.20"、"1.20.4"。
	reReleaseCore = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)
	//  Mojang 快照：两位年 + w + 1~2 位周 + 一个字母，例如 "24w14a"。
	reSnapshot = regexp.MustCompile(`^([0-9]{2})w([0-9]{1,2})([a-z])$`)
	// 预发布尾巴：-preN / -rcN（N 为数字），如 "1.21-pre1"、"1.21-rc2"。
	rePrerelease = regexp.MustCompile(`^-(pre|rc)([0-9]+)$`)
)

type MCSemVersion struct {
	Major int    // 发布主版本号（当前恒为 1）
	Minor int    // 次版本号，如 20
	Patch int    // 修订号，缺省 0
	Kind  string // release / snapshot / prerelease / unknown
	// 快照字段（仅 Kind==snapshot 时有意义）。
	SnapYear int // 两位年，如 24
	SnapWeek int // 周，如 14
	// 预发布序号（仅 Kind==prerelease 时有意义），pre/rc 统一按数字序号比较。
	PreSeq int
}

func validSegment(s string) (int, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > maxMCVersionSegment {
		return 0, false
	}
	return n, true
}

// parseReleaseCore 解析点分发布核心，返回 (major,minor,patch,ok)。
// 缺省的次 / 修订号按 0 处理。
func parseReleaseCore(core string) (int, int, int, bool) {
	if !reReleaseCore.MatchString(core) {
		return 0, 0, 0, false
	}
	parts := strings.Split(core, ".")
	nums := [3]int{0, 0, 0}
	for i, p := range parts {
		v, ok := validSegment(p)
		if !ok {
			return 0, 0, 0, false
		}
		nums[i] = v
	}
	return nums[0], nums[1], nums[2], true
}

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
