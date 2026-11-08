package main

// worldbackup.go —— 世界存档安全备份 / 恢复内核。
//
// 这是启动器该有、此前却完全缺失的一道“防丢档”能力：玩家一个世界可能玩了几百
// 小时，一次误删 / 磁盘损坏 / 版本升级存档格式不兼容都会不可逆地丢掉。本模块在
// “受信根 + 体量预算 + 原子落盘 + 清单校验”的既有安全框架内实现本地世界备份：
//
//   - 备份源只能是 <gameDir>/saves/<worldName>：gameDir 必须落在 .minecraft 之内，
//     worldName 过 auditComponent（拒绝路径分隔符 / ".." / 控制字符 / Unicode 不可见
//     与 bidi / Windows 保留设备名），解析后再用 PathWithinRoot 双重确认，挡住链接逃逸；
//   - 打包过程只收普通文件，符号链接 / 设备 / 管道 / 套接字一律拒绝（防把 saves 里
//     预先埋好的链接所指向的外部敏感文件打进备份）；
//   - 条目数 / 单文件 / 总体积三道上限防“存档即解压炸弹”撑爆备份盘，落盘前先用
//     diskspaceguard 预留安全水位，zip 走临时文件 + fsync + rename 的原子写；
//   - 备份文件统一放在 QGL/worldbackups/<world>/ 下，与游戏目录隔离；每个 zip 旁写
//     一份 0600 清单，记录条目数 / 体积 / UMFS 摘要，恢复前强制核对摘要；
//   - 恢复绝不覆盖任何已有目录：总是解压到 saves/<world>-restored-<stamp> 新目录，并
//     复用 zipextract 的 Zip Slip / 特殊条目 / 炸弹防护（空前缀=整包相对路径）。
//
// 这里的 UMFS 仅用于“本地备份完整性”用途，符合“本地用途哈希用 UMFS”的约定；
// 不涉及任何外部下载 API 的 SHA1 / SHA256 校验算法。

const (
	worldBackupRootFolder = "worldbackups"
	worldSavesFolder      = "saves"

	maxWorldNameLen = 64

	// 单世界备份的体量预算。默认值刻意覆盖主流整合包存档（通常 < 1GiB），但用
	// 明确的天花板封死“存档目录被塞几百 GB 文件 -> 备份把盘写满”的本地 DoS。
	worldKeepDefault = 8
	worldKeepMax     = 32

	worldMaxEntriesDefault = 20000
	worldMaxEntriesCeiling = 100000
	worldMaxTotalDefault   = int64(2) << 30 // 2GiB
	worldMaxTotalCeiling   = int64(8) << 30 // 8GiB
	worldMaxEntryDefault   = int64(256) << 20
	worldMaxEntryCeiling   = int64(1) << 30

	// 备份落盘除了数据本身外，额外为 zip 临时膨胀 / 目录元数据预留的安全余量。
	worldReserveHeadroom = int64(256) << 20

	worldStampLayout = "20060102-150405"
	worldStampLen    = 15
)

// WorldBackupLimits 是一次世界备份 / 恢复允许消耗的资源上限。
type WorldBackupLimits struct {
	MaxEntries    int   // 普通文件条目数上限
	MaxTotalBytes int64 // 全部文件合计字节上限
	MaxEntryBytes int64 // 单个文件字节上限
	Keep          int   // 每个世界保留的备份份数（超出按时间淘汰最旧）
}

func defaultWorldBackupLimits() WorldBackupLimits {
	return WorldBackupLimits{
		MaxEntries:    worldMaxEntriesDefault,
		MaxTotalBytes: worldMaxTotalDefault,
		MaxEntryBytes: worldMaxEntryDefault,
		Keep:          worldKeepDefault,
	}
}

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
