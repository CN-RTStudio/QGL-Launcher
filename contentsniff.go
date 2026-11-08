package main

// contentsniff.go —— 下载产物的内容嗅探（magic bytes）与类型一致性守卫。
//
// 威胁模型：
//   启动器从镜像下载大量“按扩展名/路径约定用途”的产物：.jar（库/mod）、
//   .zip（整合包/资源包）、.png（图标/皮肤）、.ogg（音效）等。现有链路做了
//   哈希校验，但哈希只能证明“和清单一致”，证明不了“它真的是该类文件”：
//     - 镜像本身被投毒 / 返回自定义错误页（200 + 一段 HTML），扩展名仍是
//       xxx.jar，哈希通过与否取决于清单是否同步被篡改；
//     - 被 MITM 或透明代理注入可执行体（Windows MZ / ELF / Mach-O / #!脚本）；
//     - 截断 / 0 字节 / 声明 zip 却没有任何中央目录结构。
//   这类文件一旦被当作 jar 交给类加载器、或当作图片交给解析器，会触发
//   解析器漏洞或直接执行。
//
// 本模块只看落盘内容的头部字节与最小结构，不解压、不执行、不依赖扩展名作为
// 唯一依据：
//   - 推断真实种类（zip/png/jpeg/gif/ogg/gzip/pdf/可执行体/脚本/文本）；
//   - 按“声明用途”要求魔数一致；
//   - 任何声明为资源的文件，只要嗅出可执行体/脚本头，一律拒绝（polyglot 防护）；
//   - 对 zip 类额外要求存在 EOCD 中央目录结束签名并有界条目数（防伪造/炸弹前奏）。
// 纯函数、不读文件系统，全部判定可穷举测试。

import (
	"bytes"
	"encoding/binary"
)

// ArtifactKind 推断出的内容种类。
type ArtifactKind string

const (
	KindUnknown   ArtifactKind = "unknown"
	KindZip       ArtifactKind = "zip"   // 含 jar（jar 是 zip 容器）
	KindPNG       ArtifactKind = "png"
	KindJPEG      ArtifactKind = "jpeg"
	KindGIF       ArtifactKind = "gif"
	KindOGG       ArtifactKind = "ogg"
	KindGzip      ArtifactKind = "gzip"
	KindPDF       ArtifactKind = "pdf"
	KindExecutable ArtifactKind = "executable" // MZ / ELF / Mach-O
	KindScript    ArtifactKind = "script"     // #! shebang
	KindTextHTML   ArtifactKind = "text-html"
)

// 嗅探用的固定签名。
var (
	sigPNG  = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	sigJPEG = []byte{0xff, 0xd8, 0xff}
	sigGIF1 = []byte("GIF87a")
	sigGIF2 = []byte("GIF89a")
	sigOGG  = []byte("OggS")
	sigGZIP = []byte{0x1f, 0x8b}
	sigPDF  = []byte("%PDF")
	sigMZ   = []byte{'M', 'Z'}
	sigELF  = []byte{0x7f, 'E', 'L', 'F'}
	sigMachO32 = []byte{0xfe, 0xed, 0xfa, 0xce}
	sigMachO64 = []byte{0xfe, 0xed, 0xfa, 0xcf}
	sigMachFat = []byte{0xca, 0xfe, 0xba, 0xbe}
	sigMachFat64 = []byte{0xca, 0xfe, 0xba, 0xbf}
	sigZIPLocal = []byte{'P', 'K', 0x03, 0x04}
	sigZIPEmpty = []byte{'P', 'K', 0x05, 0x06}
	sigZIPSpan  = []byte{'P', 'K', 0x07, 0x08}
)

// ContentSniffLimits 嗅探/结构检查的量化边界。
type ContentSniffLimits struct {
	MinArtifactBytes int
	MaxZipEntries    uint64
	MaxHeadProbe     int
}

func defaultContentSniffLimits() ContentSniffLimits {
	return ContentSniffLimits{
		MinArtifactBytes: 16,
		MaxZipEntries:    200000,
		MaxHeadProbe:     65536,
	}
}

// sniffExecutable 必须排在 zip 等常规类型之外单独调用：识别可执行体。
func sniffExecutable(head []byte) bool {
	for _, sig := range [][]byte{sigMZ, sigELF, sigMachO32, sigMachO64, sigMachFat, sigMachFat64} {
		if bytes.HasPrefix(head, sig) {
			return true
		}
	}
	return false
}

// SniffKind 依据头部字节推断内容种类。可执行体优先判定（即使伪造 zip 头之外
// 的偏移也由调用方做二次扫描，本函数只看起始魔数）。
func SniffKind(head []byte) ArtifactKind {
	if len(head) == 0 {
		return KindUnknown
	}
	switch {
	case sniffExecutable(head):
		return KindExecutable
	case bytes.HasPrefix(head, sigZIPLocal) || bytes.HasPrefix(head, sigZIPEmpty) || bytes.HasPrefix(head, sigZIPSpan):
		return KindZip
	case bytes.HasPrefix(head, sigPNG):
		return KindPNG
	case bytes.HasPrefix(head, sigJPEG):
		return KindJPEG
	case bytes.HasPrefix(head, sigGIF1) || bytes.HasPrefix(head, sigGIF2):
		return KindGIF
	case bytes.HasPrefix(head, sigOGG):
		return KindOGG
	case bytes.HasPrefix(head, sigGZIP):
		return KindGzip
	case bytes.HasPrefix(head, sigPDF):
		return KindPDF
	}
	if len(head) >= 2 && head[0] == '#' && head[1] == '!' {
		return KindScript
	}
	if looksLikeHTML(head) {
		return KindTextHTML
	}
	return KindUnknown
}

// looksLikeHTML 极保守地识别前若干字节内的 HTML / XML 错误页特征。
func looksLikeHTML(head []byte) bool {
	n := len(head)
	if n > 1024 {
		n = 1024
	}
	window := head[:n]
	// 去掉前导 BOM / 空白后匹配 <!doctype html / <html / <?xml。
	trimmed := bytes.TrimLeft(window, " \t\r\n\xef\xbb\xbf")
	low := make([]byte, len(trimmed))
	for i, b := range trimmed {
		if b >= 'A' && b <= 'Z' {
			low[i] = b + 32
		} else {
			low[i] = b
		}
	}
	for _, marker := range [][]byte{[]byte("<!doctype html"), []byte("<html"), []byte("<?xml"), []byte("<head"), []byte("<script")} {
		if bytes.HasPrefix(low, marker) {
			return true
		}
	}
	return false
}

// findEOCD 在尾部窗口里查找 zip EOCD 签名 PK\x05\x06。
func findEOCD(data []byte) int {
	if len(data) < 22 {
		return -1
	}
	start := len(data) - 65557 // EOCD + 最大注释长度窗口
	if start < 0 {
		start = 0
	}
	window := data[start:]
	idx := bytes.LastIndex(window, sigZIPEmpty)
	if idx < 0 {
		return -1
	}
	return start + idx
}

// zipEOCDInfo 从 EOCD 记录解析总条目数（16 位，磁盘中央目录条目计数位于
// EOCD+10）。返回 -1 表示结构非法。
func zipEOCDInfo(data []byte, eocd int) (entries uint64, ok bool) {
	if eocd < 0 || eocd+22 > len(data) {
		return 0, false
	}
	rec := data[eocd:]
	total := binary.LittleEndian.Uint16(rec[10:12])
	return uint64(total), true
}

// declaredKindForPurpose 把“声明用途/扩展名”映射到期望的内容种类。
func declaredKindForPurpose(purpose string) (ArtifactKind, bool) {
	switch purpose {
	case "jar", "zip", "mrpack", "modpack", "resourcepack", "world", "datapack", "natives-archive":
		return KindZip, true
	case "png", "skin", "icon", "texture":
		return KindPNG, true
	case "jpg", "jpeg":
		return KindJPEG, true
	case "gif":
		return KindGIF, true
	case "ogg", "sound", "music":
		return KindOGG, true
	case "pdf":
		return KindPDF, true
	default:
		return KindUnknown, false
	}
}

// ContentVerdict 嗅探裁决。
type ContentVerdict struct {
	OK         bool
	Reason     string
	Kind       ArtifactKind
	ZipEntries uint64
}

// SniffArtifact 校验落盘产物头部与完整字节。purpose 为声明用途（jar/png/…），
// head 为前若干字节（建议 >=32），full 为完整内容（用于 zip EOCD 结构检查）；
// 若调用方只有 head，可传 full=nil，此时跳过需要全文的结构检查。
func SniffArtifact(purpose string, head, full []byte, lim ContentSniffLimits) ContentVerdict {
	if lim.MaxZipEntries == 0 {
		lim = defaultContentSniffLimits()
	}
	want, known := declaredKindForPurpose(purpose)

	if len(head) == 0 {
		return ContentVerdict{OK: false, Reason: "empty-content", Kind: KindUnknown}
	}
	kind := SniffKind(head)

	// 通用红线：任何资源都不得是可执行体或脚本。
	if kind == KindExecutable {
		return ContentVerdict{OK: false, Reason: "executable-disguised", Kind: kind}
	}
	if kind == KindScript {
		return ContentVerdict{OK: false, Reason: "script-disguised", Kind: kind}
	}
	// 错误页 / HTML 伪装成资源（200 错误页注入）。
	if kind == KindTextHTML {
		return ContentVerdict{OK: false, Reason: "html-disguised", Kind: kind}
	}

	// 声明用途已知时要求魔数一致。
	if known {
		if kind != want {
			// gzip 包装的 zip 不在本启动器产物约定内，按不匹配拒绝。
			return ContentVerdict{OK: false, Reason: "magic-mismatch:" + string(want), Kind: kind}
		}
	}

	v := ContentVerdict{OK: true, Reason: "", Kind: kind}

	// zip 类结构检查：必须能在全文找到 EOCD 且条目数有界。
	if kind == KindZip && full != nil {
		if len(full) < 22 {
			return ContentVerdict{OK: false, Reason: "zip-truncated", Kind: kind}
		}
		eocd := findEOCD(full)
		if eocd < 0 {
			return ContentVerdict{OK: false, Reason: "zip-no-eocd", Kind: kind}
		}
		entries, ok := zipEOCDInfo(full, eocd)
		if !ok {
			return ContentVerdict{OK: false, Reason: "zip-bad-eocd", Kind: kind}
		}
		if entries == 0 && !bytes.HasPrefix(full, sigZIPEmpty) {
			return ContentVerdict{OK: false, Reason: "zip-zero-entries", Kind: kind}
		}
		if entries > lim.MaxZipEntries {
			return ContentVerdict{OK: false, Reason: "zip-too-many-entries", Kind: kind, ZipEntries: entries}
		}
		v.ZipEntries = entries
	}

	// 只有头部、没有全文时（预筛阶段），对已知用途做最小长度兜底。
	if full == nil && known && want != KindPNG && want != KindGIF {
		if len(head) < lim.MinArtifactBytes {
			return ContentVerdict{OK: false, Reason: "too-small-for-kind", Kind: kind}
		}
	}
	return v
}

// ScanDeepPolyglot 扫描头部窗口更深位置是否藏有可执行签名（某些 polyglot
// 把 MZ 放在前面若干填充字节之后）。返回命中的偏移，-1 表示未发现。
func ScanDeepPolyglot(head []byte, window int) int {
	if window <= 0 || window > len(head) {
		window = len(head)
	}
	buf := head[:window]
	for _, sig := range [][]byte{sigMZ, sigELF, sigMachO64, sigMachO32} {
		if idx := bytes.Index(buf, sig); idx >= 0 {
			return idx
		}
	}
	return -1
}
