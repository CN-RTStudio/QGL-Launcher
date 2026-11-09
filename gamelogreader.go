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
