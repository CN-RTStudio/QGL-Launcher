package main

import "math"

// mrpackinstallbudget.go —— .mrpack 客户端安装“选中文件聚合字节预算”纯逻辑内核。
//
// 既有防护里，清单单文件有 maxMrpackDeclaredFileSize（8GiB）、条目数有
// maxMrpackIndexFiles（20000），但“客户端真正要装的那批文件声明体积之和”没有上限。
// 一个恶意 / 损坏清单可以让 20000 个条目各自声明接近 8GiB，聚合声明量逼近天文数字：
// 逐文件校验都放行、实际下载时才把磁盘写穿。磁盘预检（diskplan）面向下载队列的
// SavePath，而整合包安装走自己的循环，不受其约束，因此这里单独在安装前对“被客户端
// 选取的文件”做一次聚合预算裁决。
//
// 策略延续“炸磁盘才限制”：预算取得极宽（1TiB 声明总量），正常整合包（通常几 GB ~
// 几十 GB）绝不会被拦；只有声明总量本身就离谱时才在下载前中止。声明大小未知
// （fileSize<=0，Modrinth 允许缺省）的条目按 0 计入预算、不阻断，但单独计数，由调用
// 方据此提示“这是保守下限”。本文件只做纯算术，便于确定性单测。

// maxMrpackClientInstallBytes 是客户端一次安装整合包时，选中文件声明体积之和的上限
// （1TiB）。取极大值：只拦天文数字级的异常清单，正常整合包不受影响。
const maxMrpackClientInstallBytes int64 = 1 << 40

// mrpackInstallBudgetAssessment 是一次聚合预算裁决。
type mrpackInstallBudgetAssessment struct {
	// Total 是被选取文件中“已知声明大小”的非负求和；溢出时折叠到 math.MaxInt64。
	Total int64
	// Count 是参与统计的选取文件数。
	Count int
	// KnownCount 是声明了正体积（fileSize>0）的条目数。
	KnownCount int
	// UnknownCount 是未声明 / 非正体积（按 0 计入）的条目数。
	UnknownCount int
	// Overflow 表示求和过程中发生 int64 溢出（物理上不可能的声明量）。
	Overflow bool
	// OverBudget 表示已知体积之和已超过 maxMrpackClientInstallBytes。
	OverBudget bool
}

// OK 汇总“是否允许进入下载”：既未溢出、也未超预算时为 true。
// 存在未知大小条目不影响 OK（预算是保守下限，未知条目的实际风险由实时磁盘守卫兜）。
func (a mrpackInstallBudgetAssessment) OK() bool {
	return !a.Overflow && !a.OverBudget
}

// sumMrpackSelectionBytes 对“被选取下标”对应的文件声明大小求和。
//
//	files：完整清单（已通过 validateMrpackManifest，单文件大小非负且 <= 单文件上限）；
//	kept：planClientMrpackFiles 选出的客户端文件下标；
//	越界下标忽略（防御性，正常不会出现）；
//	fileSize<=0 视为未知，按 0 计入并累加 unknown 计数。
func sumMrpackSelectionBytes(files []ModrinthModpackFile, kept []int) (total int64, known, unknown int, overflow bool) {
	for _, idx := range kept {
		if idx < 0 || idx >= len(files) {
			continue
		}
		size := files[idx].FileSize
		if size <= 0 {
			unknown++
			continue
		}
		known++
		sum, ok := addChecked(total, size)
		if !ok {
			return math.MaxInt64, known, unknown, true
		}
		total = sum
	}
	return total, known, unknown, false
}

// assessMrpackInstallBudget 对客户端选取结果做聚合预算裁决（纯函数）。
func assessMrpackInstallBudget(files []ModrinthModpackFile, kept []int) mrpackInstallBudgetAssessment {
	a := mrpackInstallBudgetAssessment{Count: len(kept)}
	a.Total, a.KnownCount, a.UnknownCount, a.Overflow =
		sumMrpackSelectionBytes(files, kept)
	if a.Overflow {
		// 溢出本身即天文数字，必然也超预算，但 Overflow 是更精确的原因码。
		a.OverBudget = true
		return a
	}
	a.OverBudget = a.Total > maxMrpackClientInstallBytes
	return a
}

// describeMrpackInstallBudget 把不通过的裁决转成面向用户的中文说明；OK 时返回空串。
func describeMrpackInstallBudget(a mrpackInstallBudgetAssessment) string {
	switch {
	case a.Overflow:
		return "整合包声明的文件总字节数溢出，清单疑似伪造，已中止安装"
	case a.OverBudget:
		return "整合包客户端文件声明总量 " + FormatBytes(a.Total) +
			" 超过上限 " + FormatBytes(maxMrpackClientInstallBytes) +
			"，疑似异常清单，已中止安装（防炸磁盘）"
	default:
		return ""
	}
}
