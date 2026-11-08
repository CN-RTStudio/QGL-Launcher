package main

// launchconfig：启动配置守卫。
//
// 场景：版本 json 的 arguments / 实例配置的 jvmArgs / 下载脚本都可能被篡改，
// 最终仲裁出的启动命令行如果带了 @argfile、-jar 二次注入、非法 -version 值，
// 可以让 JVM 加载攻击者指定的文件（绕过主 jar）。本模块对“最终启动配置”
// 做纯函数校验：
//   - 参数总数与单参数长度有界（防 argv 爆炸）；
//   - 拒绝控制字符 / 换行 / NUL；
//   - 拒绝 @argfile（r22 已在下载层拦，这里是配置层纵深）；
//   - -jar 之后不允许再出现 -jar / -cp / -version 等注入形态；
//   - -version 值必须是受信任形态（如 "1.8+" 或数字点号）；
//   - 游戏目录 / 资源目录路径必须相对实例根或绝对路径且无穿越；
//   - 用户名长度与字符集有界。

import (
	"path/filepath"
	"strings"
)

// LaunchLimits 启动配置守卫的量化边界。
type LaunchLimits struct {
	MaxArgs        int
	MaxArgLen      int
	MaxUsername    int
	AllowVersionV1 bool // 允许 "1.8+" 这类旧式 version 形态
}

func defaultLaunchLimits() LaunchLimits {
	return LaunchLimits{MaxArgs: 512, MaxArgLen: 4096, MaxUsername: 32, AllowVersionV1: true}
}

type launchVerdict struct {
	OK     bool
	Reason string
	Argv   []string // 通过校验后的净参数
}

// validateLaunchArg 校验单个启动参数。
func validateLaunchArg(arg string, lim LaunchLimits) string {
	if arg == "" {
		return "empty-arg"
	}
	if len(arg) > lim.MaxArgLen {
		return "arg-too-long"
	}
	if strings.Contains(arg, "\x00") {
		return "nul"
	}
	if hasControlCharStr(arg) {
		return "control-char"
	}
	if strings.HasPrefix(arg, "@") {
		return "argfile"
	}
	return ""
}

// versionValueOK 校验 -version 参数值。
func versionValueOK(v string, lim LaunchLimits) bool {
	if v == "" {
		return true // 不填版本时不校验
	}
	if lim.AllowVersionV1 && (v == "1.8+" || v == "1.8" || v == "1.9+") {
		return true
	}
	// 数字点号形态（如 1.20.1 / 47.1.0）
	dots := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '.' {
			dots++
			continue
		}
		return false
	}
	return dots >= 1 && dots <= 4
}

// ValidateLaunchConfig 校验启动参数数组 + 目录。
// dir 为游戏目录（instance 根），mcDir / assetsDir 可为空。
func ValidateLaunchConfig(argv []string, mcDir, assetsDir string, lim LaunchLimits) launchVerdict {
	if lim.MaxArgs == 0 {
		lim = defaultLaunchLimits()
	}
	vd := launchVerdict{OK: true}
	if len(argv) > lim.MaxArgs {
		vd.OK = false
		vd.Reason = "argv-overflow"
		return vd
	}
	clean := make([]string, 0, len(argv))
	seenJar := false
	for i, arg := range argv {
		if r := validateLaunchArg(arg, lim); r != "" {
			vd.OK = false
			vd.Reason = "arg:" + r + ":" + itoaSafe(i)
			return vd
		}
		switch arg {
		case "-jar":
			if seenJar {
				vd.OK = false
				vd.Reason = "jar-reentry:" + itoaSafe(i)
				return vd
			}
			seenJar = true
		case "-version":
			// 下一参数必须是受信任版本值
			if i+1 >= len(argv) {
				vd.OK = false
				vd.Reason = "version-missing-value"
				return vd
			}
			if !versionValueOK(argv[i+1], lim) {
				vd.OK = false
				vd.Reason = "version-illegal-value"
				return vd
			}
			clean = append(clean, argv[i+1])
			i++
			continue
		case "-cp", "-classpath", "-Djava.library.path":
			// 类路径参数必须指向受控路径；此处禁止以 -cp 开头跟 -jar 逃逸
			if seenJar {
				vd.OK = false
				vd.Reason = "cp-after-jar"
				return vd
			}
		case "--launcher", "--demo", "--quickPlay", "--fastLaunch":
			vd.OK = false
			vd.Reason = "banned-flag:" + arg
			return vd
		}
		clean = append(clean, arg)
	}
	// 目录校验
	for _, dir := range []string{mcDir, assetsDir} {
		if dir == "" {
			continue
		}
		if r := validateLaunchDir(dir); r != "" {
			vd.OK = false
			vd.Reason = "dir:" + r
			return vd
		}
	}
	vd.Argv = clean
	return vd
}

// validateLaunchDir 校验启动涉及目录：绝对路径或相对路径，均不得有穿越段。
func validateLaunchDir(dir string) string {
	if dir == "" {
		return "empty"
	}
	if hasControlCharStr(dir) {
		return "control-char"
	}
	if strings.Contains(dir, "..") {
		return "dotdot"
	}
	// Windows 盘符 / UNC 允许（合法绝对路径），但反斜杠路径必须转正后仍干净
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(dir)))
	if clean == "" || clean == "." || clean == ".." {
		return "bad-clean"
	}
	return ""
}

// ValidateUsername 校验离线用户名（用于生成会话令牌与玩家目录）。
func ValidateUsername(name string, lim LaunchLimits) string {
	if lim.MaxUsername == 0 {
		lim = defaultLaunchLimits()
	}
	if name == "" {
		return "empty"
	}
	if len(name) > lim.MaxUsername {
		return "too-long"
	}
	if hasControlCharStr(name) {
		return "control-char"
	}
	for _, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
		if !ok {
			return "illegal-char"
		}
	}
	return ""
}

// SummarizeLaunchVerdict 压成一行。
func SummarizeLaunchVerdict(vd launchVerdict) string {
	if vd.OK {
		return "launch ok args=" + itoaSafe(len(vd.Argv))
	}
	return "launch bad " + vd.Reason
}
