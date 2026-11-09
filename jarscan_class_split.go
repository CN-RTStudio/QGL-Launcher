package main

import (
	"fmt"
)

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
