package main

// displaynameguard.go —— 服务器/资源“显示名”的 Unicode 混淆检测内核（纯函数）。
//
// 威胁模型：
//   服务器列表、mod 名、MOTD 渲染层会原样展示一段用户/远端给的名字。攻击者可以在
//   名字里塞肉眼看不见或会重排排版的字符，让用户在表格里读到的是“gооgle”、
//   “PayPal官方”这类伪装：
//     1) Bidi 覆写控制字符（LRO/RLO/LRE/RLE/…）：把右到左片段强行翻转，
//        例如 "evil[RLO]moc.lebal" 在 UI 上排成 "label.com"，列对齐被搅乱；
//     2) 零宽 / 连接符（ZWJ/ZWNJ/WSBJ、各类 bidi mark）：名字肉眼对齐但宽度、
//        复制结果与看到的不一致，用于绕过“这串文字是否重复”的人工核对；
//     3) 同形异义字混写：同一显示词里混入西里尔/希腊字母冒充拉丁字母
//        （С 的 U+0421、о 的 U+043E、а 的 U+0430），即 IDN homograph 攻击。
//
// 本模块不做渲染、不联网，只给“这段显示名是否需要打标 / 是否应当转义后再展示”
// 的纯判定，便于穷举单测。返回的是分类标签集合，调用方决定是打⚠️前缀还是直接
// 转义为 \uXXXX。

import (
	"unicode"
	"unicode/utf8"
)

// displayNameFlag 是一条检测结论的稳定标签，可用于审计事件与 UI。
type displayNameFlag string

const (
	flagBidiOverride    displayNameFlag = "bidi-override"      // LRE/RLE/PDF/LRO/RLO 等强排版覆写
	flagBidiIsolate     displayNameFlag = "bidi-isolate"       // RLI/LRI/FSI/PDI 方向隔离
	flagZeroWidth       displayNameFlag = "zero-width"         // ZWJ/ZWNJ/WSBJ 等不可见宽度字符
	flagBiDiMark        displayNameFlag = "bidi-mark"          // LRM/RLM 等不可见方向标记
	flagMixedScript     displayNameFlag = "mixed-script"       // 拉丁词里混入西里尔/希腊同形字母
	flagOutOfBlockAscii displayNameFlag = "nonprintable-ascii" // 其余不可打印 ASCII
)

// bidiControlRunes 列出会强行改写双向排版的控制字符（不要求完整，覆盖常见滥用）。
var bidiControlRunes = map[rune]bool{
	0x202A: true, // LRE
	0x202B: true, // RLE
	0x202C: true, // PDF
	0x202D: true, // LRO
	0x202E: true, // RLO
}

// bidiIsolateRunes 方向隔离符：单独不一定恶意，但出现在伪装名里常配合翻转使用。
var bidiIsolateRunes = map[rune]bool{
	0x2066: true, // LRI
	0x2067: true, // RLI
	0x2068: true, // FSI
	0x2069: true, // PDI
}

// zeroWidthRunes 零宽/连接类：不可见且会改变后续组合。
var zeroWidthRunes = map[rune]bool{
	0x200B: true, // ZWSP
	0x200C: true, // ZWNJ
	0x200D: true, // ZWJ
	0x2060: true, // WJ
	0xFEFF: true, // BOM / ZWNBSP
}

// bidiMarkRunes 不可见方向标记。
var bidiMarkRunes = map[rune]bool{
	0x200E: true, // LRM
	0x200F: true, // RLM
}

// scriptKind 把一个字符粗略归到“看起来像拉丁”的几个书写系统。
type scriptKind int

const (
	scriptOther scriptKind = iota
	scriptLatin
	scriptCyrillic
	scriptGreek
)

// runeScriptKind 只挑出与拉丁互相形似的西里尔/希腊字母，其余一律归 other。
// 判定依据是 Unicode 块，而不是逐字形近表——目标是“同一 display token 里出现了
// 两个不同的、形似拉丁的字母块”，这正是 homograph 攻击的指纹。
func runeScriptKind(r rune) scriptKind {
	switch {
	case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		return scriptLatin
	case unicode.Is(unicode.Cyrillic, r):
		return scriptCyrillic
	case unicode.Is(unicode.Greek, r):
		return scriptGreek
	default:
		return scriptOther
	}
}

// inspectDisplayName 扫描一段显示名，返回命中的标签（去重、保持命中顺序）。
// 空串返回空切片。纯函数，不修改入参。
func inspectDisplayName(name string) []displayNameFlag {
	var flags []displayNameFlag
	seen := map[displayNameFlag]bool{}
	add := func(f displayNameFlag) {
		if !seen[f] {
			seen[f] = true
			flags = append(flags, f)
		}
	}

	hasLatin := false
	hasLookalike := false

	for len(name) > 0 {
		r, size := utf8.DecodeRuneInString(name)
		name = name[size:]

		switch {
		case bidiControlRunes[r]:
			add(flagBidiOverride)
		case bidiIsolateRunes[r]:
			add(flagBidiIsolate)
		case zeroWidthRunes[r]:
			add(flagZeroWidth)
		case bidiMarkRunes[r]:
			add(flagBiDiMark)
		case r < 0x20 || r == 0x7f:
			add(flagOutOfBlockAscii)
		}

		switch runeScriptKind(r) {
		case scriptLatin:
			hasLatin = true
		case scriptCyrillic, scriptGreek:
			hasLookalike = true
		}
	}

	// 只有当一个显示词同时含“真拉丁”和“西里尔/希腊形似字母”时才判混写：
	// 纯西里尔名（俄语服务器名）不该被误报，纯拉丁名也显然没问题。
	if hasLatin && hasLookalike {
		add(flagMixedScript)
	}
	return flags
}

// displayNameLooksSuspicious 是便捷布尔入口：命中任一高风险标签即视为可疑。
func displayNameLooksSuspicious(name string) bool {
	return len(inspectDisplayName(name)) > 0
}

// escapeInvisibleForDisplay 把不可见 / 强排版字符替换成可读的 [U+XXXX] 标记，
// 用于“必须展示原始名字但不能让它偷偷重排”的场景；其余字符原样保留。
func escapeInvisibleForDisplay(name string) string {
	var b []byte
	for len(name) > 0 {
		r, size := utf8.DecodeRuneInString(name)
		name = name[size:]
		switch {
		case bidiControlRunes[r], bidiIsolateRunes[r], zeroWidthRunes[r], bidiMarkRunes[r]:
			b = append(b, []byte(toHexTag(r))...)
		default:
			b = utf8.AppendRune(b, r)
		}
	}
	return string(b)
}

// toHexTag 生成 [U+XXXX] 形式的可读占位。
func toHexTag(r rune) string {
	const hex = "0123456789ABCDEF"
	var buf [8]byte
	n := copy(buf[:], []byte("[U+"))
	v := uint32(r)
	for shift := 12; shift >= 0; shift -= 4 {
		buf[n] = hex[(v>>shift)&0xF]
		n++
	}
	buf[n] = ']'
	n++
	return string(buf[:n])
}
