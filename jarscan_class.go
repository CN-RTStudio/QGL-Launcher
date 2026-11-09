package main

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"
)

func (r *JarScanReport) addRuleOnce(sev JarFindingSeverity, rule, entry, detail string) {
	if r.ruleSeen[rule] {
		return
	}
	r.ruleSeen[rule] = true
	r.add(sev, rule, entry, detail)
}

// scanClassBehavior 读取单个 class（有字节上限），只解析常量池里的 UTF8 项做能力
// 特征匹配，绝不加载 / 验证 / 执行字节码。返回实际读取的字节数（用于全局预算）；
// class 损坏或被截断时返回 0，跳过而不影响其他条目。
func scanClassBehavior(rep *JarScanReport, f *zip.File, entryName string, spent int) int {
	rc, err := f.Open()
	if err != nil {
		return 0
	}
	defer rc.Close()

	capLeft := jarScanClassBytesCap - spent
	if capLeft <= 0 {
		return 0
	}
	limit := int64(jarScanPerClassCap)
	if int64(capLeft) < limit {
		limit = int64(capLeft)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return 0
	}

	texts := classConstantPoolUTF8(data)
	if texts == nil {
		// 不是可识别的 class 结构（可能被截断），不计入已扫描配额之外的噪音。
		return 0
	}
	var blob strings.Builder
	blob.Grow(len(data))
	for _, s := range texts {
		blob.WriteString(s)
		blob.WriteByte('\n')
	}
	joined := blob.String()
	lowerJoined := strings.ToLower(joined)
	for _, p := range jarBehaviorPatterns {
		needle := strings.ToLower(p.require)
		if !strings.Contains(lowerJoined, needle) {
			continue
		}
		if p.andAlso != "" && !strings.Contains(lowerJoined, strings.ToLower(p.andAlso)) {
			continue
		}
		rep.addRuleOnce(p.sev, p.rule, entryName, p.detail)
	}
	return len(data)
}

// classReader 是带边界检查的 class 文件只读游标，越界后 ok=false 并短路。
type classReader struct {
	b   []byte
	off int
	ok  bool
}

func (r *classReader) u1() int {
	if !r.ok || r.off+1 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])
	r.off++
	return v
}

func (r *classReader) u2() int {
	if !r.ok || r.off+2 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<8 | int(r.b[r.off+1])
	r.off += 2
	return v
}

func (r *classReader) u4() int {
	if !r.ok || r.off+4 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<24 | int(r.b[r.off+1])<<16 | int(r.b[r.off+2])<<8 | int(r.b[r.off+3])
	r.off += 4
	return v
}

func (r *classReader) take(n int) []byte {
	if !r.ok || n < 0 || r.off+n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

// classConstantPoolUTF8 最小化解析 class 文件，仅提取常量池 CONSTANT_Utf8 项。
// JVM 规范里类名 / 方法名字符串都以 UTF8 常量存放，能力特征匹配只需要这些文本。
// 结构非法（魔数不符 / 长度越界）返回 nil。
func classConstantPoolUTF8(data []byte) []string {
	if len(data) < 10 {
		return nil
	}
	r := &classReader{b: data, ok: true}
	if r.u4() != 0xCAFEBABE {
		return nil
	}
	r.u2() // minor_version
	r.u2() // major_version
	cpCount := r.u2()
	if cpCount == 0 {
		return nil
	}

	out := make([]string, 0, 16)
	// 常量池索引从 1 开始；Long/Double 占两个槽位。
	for idx := 1; idx < cpCount && r.ok; idx++ {
		tag := r.u1()
		switch tag {
		case 1: // CONSTANT_Utf8
			n := r.u2()
			if b := r.take(n); b != nil {
				out = append(out, string(b))
			}
		case 3, 4: // Integer, Float
			r.take(4)
		case 5, 6: // Long, Double（占两个槽位）
			r.take(8)
			idx++
		case 7, 8, 16, 19, 20: // Class, String, MethodType, Module, Package
			r.take(2)
		case 9, 10, 11, 12, 17, 18: // Fieldref..NameAndType, Dynamic, InvokeDynamic
			r.take(4)
		case 15: // MethodHandle: reference_kind(u1) + reference_index(u2)
			r.take(3)
		default:
			// 未知 / 截断的 tag：该 class 不可信，放弃解析。
			return nil
		}
	}
	if !r.ok {
		return nil
	}
	return out
}

// enforceModJarScan 是 Mod 安装链统一入口：扫描磁盘上的 jar，把每条发现写入
// 安全审计日志，出现 critical 或文件本身损坏时返回错误（调用方负责删除未落定
// 成的临时文件 / 终止导入）。source 仅用于审计，取值如 "mod-download" /
// "mod-import"；label 是文件名或 URL，会被脱敏限长。
func enforceModJarScan(jarPath, source, label string) (*JarScanReport, error) {
	rep, err := scanJarAt(jarPath)
	if err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			source, "jar 无法解析，拒绝进入 mods 目录: "+sanitizeLogLine(label))
		return nil, err
	}

	var critical int
	for _, f := range rep.Findings {
		action := auditActionStripped
		if f.Severity == JarSeverityCritical {
			action = auditActionBlocked
			critical++
		}
		detail := fmt.Sprintf("[%s] %s %s", f.Rule, f.Entry, f.Detail)
		recordSecurityEvent(auditCategoryJarScan, string(f.Severity), action, source,
			sanitizeLogLine(detail))
	}

	if critical > 0 {
		return rep, fmt.Errorf("Mod jar 静态扫描发现 %d 个高危项（如根目录可执行载荷），已阻止安装: %s",
			critical, sanitizeLogLine(label))
	}
	return rep, nil
}
