package main

import (

)

func (a *App) fixForgeModuleConflict(args []string) []string {
	result := make([]string, 0, len(args)+3)

	for i := 0; i < len(args); i++ {
		// 在 --add-modules ALL-MODULE-PATH 之后添加 --limit-modules
		if args[i] == "--add-modules" && i+1 < len(args) && args[i+1] == "ALL-MODULE-PATH" {
			result = append(result, args[i])
			result = append(result, args[i+1])
			// 插入 --limit-modules，限制模块加载范围
			result = append(result, "--limit-modules")
			result = append(result, "cpw.mods.bootstraplauncher,cpw.mods.securejarhandler,org.ow2.asm.asm,org.ow2.asm.asm-commons,org.ow2.asm.asm-tree,org.ow2.asm.asm-util,org.ow2.asm.asm-analysis,net.minecraftforge.jarjarfilesystems,java.base,java.logging,java.desktop,java.instrument,java.management,java.naming,java.prefs,java.security.sasl,jdk.attach,jdk.crypto.cryptoki,jdk.crypto.ec,jdk.jfr,jdk.library.loadhook,jdk.management.agent,jdk.naming.dns,jdk.nio.fs,jdk.sctp,jdk.unsupported,jdk.unsupported.desktop,jdk.zipfs")
			a.writeLog("修复模块冲突: 添加 --limit-modules（避免 minecraft 和 _1._19._2 冲突）")
			i++
			continue
		}
		result = append(result, args[i])
	}

	return result
}

// deduplicateJvmArgs JVM 参数去重（参考 PCL 的 DeDuplicateDataList 逻辑）
// PCL 注释: "如果不合并，会导致 Forge 1.17 启动无效，它有两个 --add-exports，
//          进一步导致其中一个在后面被去重丢失"
// 关键：使用"参数键+完整值"作为去重依据，而不是仅用键。
// 这样两个 --add-exports（值不同）都会保留，而真正重复的才会被去除。
