package main

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
