package main

import (
	"strings"
)

// 背景：downloadJavaItem 把 Java 安装包下到 %TEMP% 后调用 runInstaller 执行。
// 这条链路上有两个真实的可利用点：
//
//  1. TEMP 预置文件：%TEMP% 对同一用户下运行的其它程序是可写的。恶意程序可以
//     提前在 TEMP 放一个与 target.FileName 同名的 msi/exe，旧逻辑发现文件已
//     存在就直接 runInstaller 执行它——等于"你点下载 Java，实际运行了别人
//     预埋的安装包"。
//
//  2. 路径本身：runInstaller 只检查了扩展名，没检查文件是不是符号链接 / 设备 /
//     管道（isSymlinkOrSpecial），也没防 NTFS 备用数据流（"C:\...\x.exe:evil"
//     这种带第二个冒号的路径），更没限制大小。msiexec / explorer 拿到这种路径
//     的行为并不等价于"运行一个普通 exe"。
//
// 本文件只做"要执行的安装包是否可信为普通文件"的判定，不涉及下载来源校验
// （那部分由 HTTPS + MaxBytesReader 负责）。

const minJavaInstallerBytes int64 = 4 * 1024

// containsControlChar 判断字符串是否含 NUL 等控制字符。这类字符混进路径 /
// 命令行参数会在不同的 Win32 API 边界产生奇怪的截断行为，直接拒绝。
func containsControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// hasAlternateDataStream 判断 Windows 路径是否引用了 NTFS 备用数据流。
// 形如 "C:\Temp\jdk.exe:secret"：卷首的 "C:" 冒号合法，之后再出现冒号即 ADS。
// UNC 路径（\\server\share\...）里不应出现任何冒号。
func hasAlternateDataStream(absPath string) bool {
	p := absPath
	// 卷路径 "X:\" / "X:file"：跳过前两个字符的卷标冒号。
	if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		p = p[2:]
	}
	return strings.ContainsRune(p, ':')
}
