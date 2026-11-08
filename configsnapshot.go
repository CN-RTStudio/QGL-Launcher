package main

// configsnapshot.go —— 关键配置防篡改基线比对内核。
//
// 威胁模型：Java 路径、内存上限、游戏目录、版本选择等关键配置持久化在磁盘
// 配置文件里。若配置被非本进程的外部程序篡改（木马把 javaPath 指向自己投放
// 的 exe、把版本目录换掉），下一次启动会“按用户上次的选择”拉起恶意目标。
// 静态校验（checkJavaBinary 拒绝符号链接等）只能挡“外观异常”，挡不住“指向
// 另一个合法外观的恶意文件”。
//
// 做法：对关键字段构建归一化快照并持久化；本进程每次可信写入配置（SaveUser
// Config / SaveGlobalConfig）时同步刷新基线；启动预检时比对基线，发现关键
// 字段在两次本进程会话之间被改动 → critical 审计并拒绝启动，防配置投毒。
//
// 纯函数层不触盘，落盘复用有界私有写。

import (
	"strings"
)

// configSnapshot 是一次关键配置的归一化快照。
type configSnapshot struct {
	JavaPath      string `json:"javaPath"`
	MaxMemMB      int64  `json:"maxMemMB"`
	GameDir       string `json:"gameDir"`
	VersionID     string `json:"versionID"`
	AuthTypeLabel string `json:"authTypeLabel"`
}

// configSnapshotDiff 是快照与基线比对的结果。
type configSnapshotDiff struct {
	Changed bool
	Fields  []string // 变化字段的人类可读描述
}

// configSnapshotChanged 比较当前快照与基线（归一化差异被忽略，如路径大小写
// 与尾分隔符）。基线字段为空串 / 0 时跳过该项（未建立过基线视为首次）。
func configSnapshotChanged(base, cur configSnapshot) configSnapshotDiff {
	var d configSnapshotDiff
	if base.JavaPath != "" && normSnapshotPath(base.JavaPath) != normSnapshotPath(cur.JavaPath) {
		d.Changed = true
		d.Fields = append(d.Fields, "Java 路径")
	}
	if base.MaxMemMB != 0 && base.MaxMemMB != cur.MaxMemMB {
		d.Changed = true
		d.Fields = append(d.Fields, "内存上限")
	}
	if base.GameDir != "" && normSnapshotPath(base.GameDir) != normSnapshotPath(cur.GameDir) {
		d.Changed = true
		d.Fields = append(d.Fields, "游戏目录")
	}
	if base.VersionID != "" && base.VersionID != cur.VersionID {
		d.Changed = true
		d.Fields = append(d.Fields, "版本选择")
	}
	if base.AuthTypeLabel != "" && base.AuthTypeLabel != cur.AuthTypeLabel {
		d.Changed = true
		d.Fields = append(d.Fields, "登录类型")
	}
	return d
}

// normSnapshotPath 归一化路径用于比对：小写、去首尾空白、去尾分隔符、统一斜杠。
func normSnapshotPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimRight(p, "/\\")
	return strings.ToLower(p)
}

// configSnapshotEqual 判断两份快照完全一致（落盘前判断是否真的变了）。
func configSnapshotEqual(a, b configSnapshot) bool {
	return normSnapshotPath(a.JavaPath) == normSnapshotPath(b.JavaPath) &&
		a.MaxMemMB == b.MaxMemMB &&
		normSnapshotPath(a.GameDir) == normSnapshotPath(b.GameDir) &&
		a.VersionID == b.VersionID &&
		a.AuthTypeLabel == b.AuthTypeLabel
}

// configSnapshotDiffsText 把变化字段整理成一行审计文本。
func configSnapshotDiffsText(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return "关键配置被外部篡改: " + strings.Join(fields, "、")
}

// configSnapshotSanitize 对快照字段做收口（控制字符剥离 + 限长），防把畸形
// 值写进基线文件本身。
func configSnapshotSanitize(s configSnapshot) configSnapshot {
	return configSnapshot{
		JavaPath:      sanitizeLedgerField(s.JavaPath, 1024),
		MaxMemMB:      s.MaxMemMB,
		GameDir:       sanitizeLedgerField(s.GameDir, 1024),
		VersionID:     sanitizeLedgerField(s.VersionID, 128),
		AuthTypeLabel: sanitizeLedgerField(s.AuthTypeLabel, 32),
	}
}
