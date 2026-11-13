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
