package main

import (
	"unicode/utf8"
)

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
