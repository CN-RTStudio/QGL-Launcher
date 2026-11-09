package main

// normalizeWorldBackupLimits 把外部传入 / 缺省的上限收敛到合法区间。零值取默认，
// 负值折叠为 0 再取默认，任何高于天花板的值压回天花板——调用方无法借自定义上限
// 绕过磁盘 DoS 防护。
func normalizeWorldBackupLimits(l WorldBackupLimits) WorldBackupLimits {
	n := defaultWorldBackupLimits()
	if l.MaxEntries > 0 {
		n.MaxEntries = l.MaxEntries
	}
	if l.MaxTotalBytes > 0 {
		n.MaxTotalBytes = l.MaxTotalBytes
	}
	if l.MaxEntryBytes > 0 {
		n.MaxEntryBytes = l.MaxEntryBytes
	}
	if l.Keep > 0 {
		n.Keep = l.Keep
	}
	if n.MaxEntries > worldMaxEntriesCeiling {
		n.MaxEntries = worldMaxEntriesCeiling
	}
	if n.MaxTotalBytes > worldMaxTotalCeiling {
		n.MaxTotalBytes = worldMaxTotalCeiling
	}
	if n.MaxEntryBytes > worldMaxEntryCeiling {
		n.MaxEntryBytes = worldMaxEntryCeiling
	}
	if n.Keep > worldKeepMax {
		n.Keep = worldKeepMax
	}
	if n.MaxEntryBytes > n.MaxTotalBytes {
		n.MaxEntryBytes = n.MaxTotalBytes
	}
	return n
}

// WorldInfo 是 saves 目录下一个世界目录的概要。
type WorldInfo struct {
	Name       string `json:"name"`
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	ModTime    string `json:"modTime"`
}

// WorldBackupMeta 是单个备份 zip 旁边的清单。UMFS 字段为备份内容的本地完整性摘要。
type WorldBackupMeta struct {
	WorldName  string `json:"worldName"`
	Stamp      string `json:"stamp"`
	CreatedAt  string `json:"createdAt"`
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	ZipName    string `json:"zipName"`
	UMFS       string `json:"umfs"`
}

// worldPlannedFile 是预检通过、等待写入 zip 的一个普通文件。
type worldPlannedFile struct {
	abs  string
	rel  string // 统一 '/' 分隔、相对世界根的路径
	size int64
}

type worldError string

func (e worldError) Error() string { return string(e) }

// validateWorldName 校验世界目录名单段，复用 nameguard 的统一落盘名审计。
