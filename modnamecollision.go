package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
