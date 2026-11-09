package main

import (
	"os"
)

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
