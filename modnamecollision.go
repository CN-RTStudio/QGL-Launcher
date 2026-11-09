package main

import (
	"path/filepath"
	"strings"
)

// modnamecollision.go —— “同一 mods 目录内文件名碰撞”纯逻辑裁决内核。
//
// 威胁模型：
//   Modrinth 元数据里的文件名、用户手动导入的文件名都不可信。nameguard 解决的是
//   “单个名字段本身非法”，但它是逐名字独立判断的，看不到“同一个目录里已经有谁”。
//   在 NTFS（Windows）/ APFS（macOS 默认）这类大小写不敏感、且会在落盘时剥掉尾点 /
//   尾空格的文件系统上，下面几组名字实际指向同一个文件：
//       Sodium.jar  == sodium.jar  == SODIUM.JAR
//       mod.jar     == mod.jar.     == "mod.jar "
//
//   旧下载链在目标路径已存在时直接 return nil 静默跳过：
//       1. 攻击者 / 旧版本可以预先放一个 "Sodium.jar"，新下载的 "sodium.jar" 会
//          命中同一文件而被静默跳过——用户以为装上了 Modrinth 上哈希校验过的新 Mod，
//          实际被 Mod 加载器加载的是目录里那个未经验证的旧 / 恶意 jar；
//       2. 同一整合包两个仅大小写不同的文件会互相覆盖，后到的丢、先到的伪装成后到的。
//
// 本内核只做纯计算（键归并 / 碰撞判定 / 唯一化命名），不直接读文件系统；读目录由
// listModDirNames 单独承担，便于对纯函数做表驱动单测。

// maxModNameUniquifyAttempts 限制唯一化时追加序号的尝试次数，避免目录被塞满
// "x (n).jar" 时无限循环；超过后由调用方放弃本次落盘。
const maxModNameUniquifyAttempts = 10000

// modNameCollisionKey 把名字归并成“在大小写不敏感 + 尾点 / 尾空格剥除的文件系统上
// 是否指向同一文件”的比较键：
//   - 先 filepath.Base 去掉任何目录组件（纵深防御，调用方一般已去过）；
//   - 再剥掉 Windows 落盘时会忽略的尾随 '.' 与空格；
//   - 最后整体转小写。
//
// 返回的键为空表示名字不可用作比较（调用方应已先用 nameguard 拒绝）。
func modNameCollisionKey(name string) string {
	base := filepath.Base(name)
	stripped := strings.TrimRight(base, ". ")
	return strings.ToLower(stripped)
}

// splitModStemExt 分离“主名”与“扩展名”，序号要插在扩展名之前
// （"sodium.jar" -> "sodium" / ".jar"，"core.jar.disabled" -> "core" / ".jar.disabled"）。
// 复合扩展名 .jar.disabled 必须整体识别，否则会把序号插成 "core.jar (2).disabled"。
func splitModStemExt(name string) (string, string) {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".jar.disabled") {
		cut := len(name) - len(".jar.disabled")
		return name[:cut], name[cut:]
	}
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[:i], name[i:]
	}
	return name, ""
}

// findModNameCollision 在已存在名字集合里查找与 candidate 指向同一文件的条目，
// 返回被撞的现存名字；找不到返回 false。比较一律走碰撞键。
func findModNameCollision(existing []string, candidate string) (string, bool) {
	key := modNameCollisionKey(candidate)
	if key == "" {
		return "", false
	}
	for _, has := range existing {
		if modNameCollisionKey(has) == key {
			return has, true
		}
	}
	return "", false
}
