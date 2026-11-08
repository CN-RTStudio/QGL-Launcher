package main

// gamelogreader.go —— 游戏子进程 stdout/stderr 的“有界流式按行读取”内核。
//
// 威胁模型：
//   watchGameProcess 历史上用 bufio.Scanner 的默认配置读游戏输出。Scanner 单条
//   token 上限是 bufio.MaxScanTokenSize（64KiB）。Minecraft 日志并不总是短行：
//   模组在崩溃时会把整段 NBT / 堆栈 / 注册表 dump 进一行，多人游戏里服务器也能
//   通过聊天 / MOTD 把攻击者可控文本送进 stdout。一旦某行超过 64KiB，Scanner.Scan
//   返回 bufio.ErrTooLong 并“永久停止”——对应读取 goroutine 静默退出，之后所有
//   崩溃关键词检测、启动进度检测全部失效，启动器会把已经崩溃的游戏误判成运行中。
//
//   常见修法是把 Buffer 调到很大，但那只是抬高门槛：一个不输出换行、持续刷
//   几百 MiB 的恶意服务器仍能把单行撑到内存爆掉（OOM）。
//
// 收口策略两头都堵：
//   - 流式分块读取，内部只保留“当前未结束行”，且长度硬性有界；
//   - 行超过 maxGameLogLineBytes 时保留前缀并追加截断标记，剩余字节直接丢弃到
//     该行结束（不累积、不分配），计入 TruncatedLines 供调用方审计；
//   - 正常行原样返回（去掉行尾 CR/LF），不做脱敏——脱敏仍是 sanitizeLogLine 的
//     职责，这里只管“切分”和“体积有界”，便于单独穷举测试。
//
// boundedLineSplitter 是不接触 IO 的纯状态机，喂任意分块的结果都应与“整体读入
// 再切行”一致（超长行除外）；streamBoundedLines 把 io.Reader 接到状态机上。

import (
	"io"
	"strings"
)

const (
	// maxGameLogLineBytes 是单条游戏日志行保留的最大字节数（1MiB）。
	// 远超正常日志行，足以容纳常见模组 dump；又给无换行巨行封死内存上限。
	maxGameLogLineBytes = 1 << 20
	// gameLogReadChunkBytes 是每次从管道读取的块大小。
	gameLogReadChunkBytes = 64 << 10

	// 下面三个常量约束“送进 Wails 崩溃事件的最近日志”，与内部按行读取上限解耦：
	// 内部检测需要保留较长行（模组 dump），但前端弹窗只需要可读的上下文，没必要
	// 把 20 条 1MiB 的行（最坏 20MiB）塞进一次事件。
	maxCrashContextLines  = 20
	maxGameLogUILineBytes = 2 << 10
	maxCrashContextBytes  = 16 << 10
)

// gameLogTruncateMarker 追加在被截断行末尾，标明该行不完整。
const gameLogTruncateMarker = " …[日志行过长已截断]"

// boundedLineSplitter 是字节流 -> 逻辑行的有界切分状态机。
//
// 用法：对每次读到的块调用 Feed，拿到本次收尾的若干行；流结束调用 Flush 取出
// 最后一行（可能没有换行结尾）。buf 只保存“当前未结束行”，长度不超过 maxLine；
// overflow 期间 buf 不再增长，进来的字节一律丢弃直到下一个换行。
type boundedLineSplitter struct {
	maxLine   int
	buf       []byte
	overflow  bool
	lines     int64
	truncated int64
}

// newBoundedLineSplitter 以单行字节上限构造切分器；maxLine<=0 取默认上限。
func newBoundedLineSplitter(maxLine int) *boundedLineSplitter {
	if maxLine <= 0 {
		maxLine = maxGameLogLineBytes
	}
	return &boundedLineSplitter{maxLine: maxLine}
}

// Lines 返回至今切出的逻辑行总数（含被截断的行）。
func (s *boundedLineSplitter) Lines() int64 { return s.lines }

// TruncatedLines 返回至今因超过单行上限而被截断的行数。
func (s *boundedLineSplitter) TruncatedLines() int64 { return s.truncated }

// clippedPrefix 在保证“前缀+截断标记”总长不超过 maxLine 的前提下取前缀。
func (s *boundedLineSplitter) clippedPrefix(data []byte) string {
	keep := s.maxLine - len(gameLogTruncateMarker)
	if keep < 0 {
		keep = 0
	}
	if keep > len(data) {
		keep = len(data)
	}
	return string(data[:keep]) + gameLogTruncateMarker
}

// finishLineAtNewline 处理一个恰好在本块遇到换行的段（seg 不含 '\n'）。
// 丢弃态遇到换行只负责复位；正常态把 buf+seg 合成一行，超长则就地截断
// （该行已结束，不需要进入丢弃态）。
func (s *boundedLineSplitter) finishLineAtNewline(seg []byte) (string, bool) {
	if s.overflow {
		s.overflow = false
		return "", false
	}
	combined := seg
	if len(s.buf) > 0 {
		combined = append(s.buf, seg...)
		s.buf = s.buf[:0]
	}
	if len(combined) > 0 && combined[len(combined)-1] == '\r' {
		combined = combined[:len(combined)-1]
	}
	s.lines++
	if len(combined) <= s.maxLine {
		return string(combined), true
	}
	s.truncated++
	return s.clippedPrefix(combined), true
}

// absorbTrailing 处理“本块剩余部分不再含换行”的数据，返回可能立即产出的
// 截断行（仅在当前未结束行确认超过上限那一刻产出一次）。
func (s *boundedLineSplitter) absorbTrailing(part []byte) string {
	if s.overflow {
		return ""
	}
	room := s.maxLine - len(s.buf)
	if room >= len(part) {
		// 全部放得下（含恰好放满）：暂存，等后续换行再判定。
		s.buf = append(s.buf, part...)
		return ""
	}
	// 合并后严格超过上限：立刻产出截断前缀，后续字节丢弃直到该行换行。
	if room > 0 {
		s.buf = append(s.buf, part[:room]...)
	}
	prefix := s.clippedPrefix(s.buf)
	s.buf = s.buf[:0]
	s.overflow = true
	s.lines++
	s.truncated++
	return prefix
}

// Feed 送入一个读取块，返回这块数据内已经收尾 / 提前截断的逻辑行（不含换行）。
// 分块边界任意：可以从一行中间切开，也可以从 CR 与 LF 之间切开。
func (s *boundedLineSplitter) Feed(chunk []byte) []string {
	if len(chunk) == 0 {
		return nil
	}
	var produced []string
	for len(chunk) > 0 {
		i := indexByte(chunk, '\n')
		if i < 0 {
			if line := s.absorbTrailing(chunk); line != "" {
				produced = append(produced, line)
			}
			break
		}
		if line, ok := s.finishLineAtNewline(chunk[:i]); ok {
			produced = append(produced, line)
		}
		chunk = chunk[i+1:]
	}
	return produced
}

// Flush 在流结束时取出最后一个没有换行结尾的行；无残余返回 nil。
func (s *boundedLineSplitter) Flush() []string {
	if s.overflow {
		// 流在丢弃态结束：截断前缀此前已产出并计数，这里只复位。
		s.overflow = false
		return nil
	}
	if len(s.buf) == 0 {
		return nil
	}
	rest := s.buf
	s.buf = nil
	if len(rest) > 0 && rest[len(rest)-1] == '\r' {
		rest = rest[:len(rest)-1]
	}
	s.lines++
	if len(rest) <= s.maxLine {
		return []string{string(rest)}
	}
	s.truncated++
	return []string{s.clippedPrefix(rest)}
}

// indexByte 查找字节 c 第一次出现的位置，不存在返回 -1。
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

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
