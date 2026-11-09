package main

import (
	"io"
	"strings"
)

// streamBoundedLines 持续从 r 读取并按行回调 yield，直到 EOF 或读取错误。
// 返回总行数、被截断行数与读取错误；yield 按顺序收到完整行（无换行符）。
func streamBoundedLines(r io.Reader, maxLine int, yield func(string)) (lines, truncated int64, err error) {
	s := newBoundedLineSplitter(maxLine)
	buf := make([]byte, gameLogReadChunkBytes)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			for _, line := range s.Feed(buf[:n]) {
				yield(line)
			}
		}
		if rerr == io.EOF {
			for _, line := range s.Flush() {
				yield(line)
			}
			return s.Lines(), s.TruncatedLines(), nil
		}
		if rerr != nil {
			return s.Lines(), s.TruncatedLines(), rerr
		}
	}
}

// stripLogControlChars 去掉日志行里可能干扰终端/前端渲染的控制字符，保留制表符。
// 实现统一委托 motdguard 的 stripDisplayControlChars（同一套显式 rune 判定），
// 避免两处控制字符策略漂移；换行符在按行阶段已被切走，这里只会遇到残余 CR。
func stripLogControlChars(line string) string {
	return stripDisplayControlChars(line)
}

// boundCrashContextLine 把一条日志行收敛成可放进崩溃上下文的形态：先走完整
// 展示净化（整段剥终端序列 + § 格式码 + 双向/隐形字符 + 残余控制字符，见
// motdguard），再按字节裁剪到 maxGameLogUILineBytes 并追加截断标记。
// 单剥 ESC 会残留 “[31m” 这类可见垃圾，整段剥除同时防注入与防乱码。
func boundCrashContextLine(line string) string {
	clean := stripTerminalSequences(line)
	clean = stripMCFormatCodes(clean)
	clean = stripBidiAndInvisibles(clean)
	clean = stripDisplayControlChars(clean)
	if len(clean) <= maxGameLogUILineBytes {
		return clean
	}
	keep := maxGameLogUILineBytes - len(gameLogTruncateMarker)
	if keep < 0 {
		keep = 0
	}
	return clean[:keep] + gameLogTruncateMarker
}

// buildCrashContext 把最近若干行日志组装成“有界、不含控制字符”的崩溃上下文文本。
// lines 应为已经切好的逻辑行（调用方负责只传最后 maxCrashContextLines 条之内的
// 切片，这里仍再收一次行数上限）。聚合后总字节不超过 maxCrashContextBytes：
// 超预算时丢弃更早的行，只保留靠后的上下文——崩溃定位看的就是结尾。
func buildCrashContext(lines []string) string {
	if len(lines) > maxCrashContextLines {
		lines = lines[len(lines)-maxCrashContextLines:]
	}

	bounded := make([]string, 0, len(lines))
	for _, l := range lines {
		bounded = append(bounded, boundCrashContextLine(l))
	}

	// 从最后一行向前累加，保证预算耗尽时留下的是最靠近崩溃的行。
	selected := make([]string, 0, len(bounded))
	used := 0
	for i := len(bounded) - 1; i >= 0; i-- {
		add := len(bounded[i])
		if len(selected) > 0 {
			add++ // 行间换行符
		}
		if used+add > maxCrashContextBytes {
			break
		}
		used += add
		selected = append(selected, bounded[i])
	}

	// selected 目前是倒序，翻回时间正序后再 join。
	for i, j := 0, len(selected)-1; i < j; i, j = i+1, j-1 {
		selected[i], selected[j] = selected[j], selected[i]
	}
	return strings.Join(selected, "\n")
}
