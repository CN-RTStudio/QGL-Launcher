package main

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
