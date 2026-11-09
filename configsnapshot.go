package main

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
