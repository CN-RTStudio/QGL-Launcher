package main

import (
	"strings"
	"unicode/utf8"
)

// CreateProcess 的 lpCommandLine 上限是 32767 个字符。MC 启动拼出的命令行里
// -cp classpath 会把几十个 jar 用分号连成一长串，超限时 CreateProcess 直接失败，
// 报的错又很晦涩。这里只做"长度"这一件事的纯估算，不重复 gamecmdline.go 的参数
// 引用 / 转义规则；让调用方在真正 spawn 之前拿到确定的超限结论与最长参数位置。

const createProcessCommandLineMaxChars = 32767

type argvLengthReport struct {
	Argc   int
	Chars  int
	Bytes  int
	Limit  int
	Over   bool
	Longest int
}

// joinArgvForEstimate 用单个空格拼接参数，仅用于长度估算，不做任何 shell 引用。
func joinArgvForEstimate(argv []string) string {
	return strings.Join(argv, " ")
}

// commandLineChars 返回拼接后命令行的字符数（按 Unicode 码点计，与 Windows 字符
// 上限口径一致）。
func commandLineChars(argv []string) int {
	if len(argv) == 0 {
		return 0
	}
	return utf8.RuneCountInString(joinArgvForEstimate(argv))
}

// longestArgIndex 返回最长参数（按字节）的下标；classpath 通常就是它。全空时
// 返回 -1。
func longestArgIndex(argv []string) int {
	best := -1
	bestLen := 0
	for i, a := range argv {
		if len(a) > bestLen {
			bestLen = len(a)
			best = i
		}
	}
	return best
}

// argvLengthReportFor 给出完整的长度预算报告。
func argvLengthReportFor(argv []string) argvLengthReport {
	joined := joinArgvForEstimate(argv)
	chars := 0
	if len(argv) > 0 {
		chars = utf8.RuneCountInString(joined)
	}
	return argvLengthReport{
		Argc:    len(argv),
		Chars:   chars,
		Bytes:   len(joined),
		Limit:   createProcessCommandLineMaxChars,
		Over:    chars > createProcessCommandLineMaxChars,
		Longest: longestArgIndex(argv),
	}
}

// headroomFor 返回距离上限还剩多少字符；已超限时返回负值。
func headroomFor(argv []string) int {
	return createProcessCommandLineMaxChars - commandLineChars(argv)
}
