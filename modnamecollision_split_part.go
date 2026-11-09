package main

import "os"

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
