package main

import (
	"os"
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
// 返回的键为空表示名字不可用作比较（调用方应已先用 nameguard 拒绝）。
func modNameCollisionKey(name string) string {
	base := filepath.Base(name)
	stripped := strings.TrimRight(base, ". ")
	return strings.ToLower(stripped)
}

// splitModStemExt 分离“主名”与“扩展名”，序号要插在扩展名之前
//（"sodium.jar" -> "sodium" / ".jar"，"core.jar.disabled" -> "core" / ".jar.disabled"）。
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

// uniquifyModName 在 desired 与 existing 碰撞时，按 "主名 (n)扩展名" 派生不碰撞的
// 新名字，n 从 2 开始。每派生出一个名字就把它也加入“已占用”集合继续探测，因此
// 即使目录里已经有 "a (2).jar" 也会继续跳到 "a (3).jar"。
// 无碰撞时原样返回 desired 与 collided=false；超过尝试上限返回 ok=false。
func uniquifyModName(existing []string, desired string) (string, bool, bool) {
	if _, hit := findModNameCollision(existing, desired); !hit {
		return desired, false, true
	}
	occupied := make(map[string]bool, len(existing)+8)
	for _, n := range existing {
		if k := modNameCollisionKey(n); k != "" {
			occupied[k] = true
		}
	}
	stem, ext := splitModStemExt(desired)
	for n := 2; n <= maxModNameUniquifyAttempts; n++ {
		candidate := stem + " (" + itoaModName(n) + ")" + ext
		key := modNameCollisionKey(candidate)
		if key != "" && !occupied[key] {
			return candidate, true, true
		}
		occupied[key] = true
	}
	return "", true, false
}

// itoaModName 用最小手写整数转换，避免为了序号拼接引入 strconv 的调用风格分歧。
func itoaModName(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// listModDirNames 读取目录内全部条目名（文件与子目录都算作“被占用”，避免新文件
// 与同名目录在大小写不敏感卷上相撞）。目录不存在时返回空切片，由调用方决定是否
// 需要先建目录。
func listModDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// planModDestName 给定 mods 目录与期望文件名，返回最终应落盘的名字、是否发生了
// 碰撞改名、以及错误。调用方必须先用 nameguard 保证 desired 是合法单段文件名。
// 返回 collided=true 表示目录里已有大小写 / 尾点等价的同名文件，已自动改名避让；
// 调用方应据此记一条安全事件，而不是静默复用那个未经验证的旧文件。
func planModDestName(dir string, desired string) (finalName string, collided bool, err error) {
	existing, err := listModDirNames(dir)
	if err != nil {
		return "", false, err
	}
	final, hit, ok := uniquifyModName(existing, desired)
	if !ok {
		return "", false, errModNameUniquifyLimit
	}
	return final, hit, nil
}

// errModNameUniquifyLimit 在目录里同名文件过多、无法在尝试上限内找到空位时返回。
var errModNameUniquifyLimit = modNameError("目录内同名文件过多，无法为 Mod 分配不碰撞的文件名")

// modNameError 是本模块的固定文案错误类型，避免对外暴露 os 层细节。
type modNameError string

func (e modNameError) Error() string { return string(e) }
