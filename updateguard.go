package main

// updateguard.go —— 启动器自更新包校验内核。
//
// 自更新是 MC 启动器最常被利用的供应链攻击面：若更新包下载 URL / 版本比较 /
// 包内结构不做校验，攻击者可以做三件事：
//
//  1. 版本回滚降级：把"版本比较"实现成字符串字典序（"9.9" > "9.10" 的经典
//     错误），或接受一个比当前更旧的版本号，诱使启动器"升级"到带漏洞的旧版；
//  2. MITM / 换源投毒：更新 URL 允许 http、IP 直连、带用户信息，或域名不受
//     约束，中间人可直接换包；
//  3. 包内结构攻击：更新包 zip 里藏 ../ 路径穿越 / 符号链接 / 超量条目，
//     解压时覆盖启动器目录之外的文件。
//
// 本内核只做纯校验，不执行下载与解压；调用方按 verdict 决定是否安装。
// 对外部厂商哈希（Mojang/authlib/Modrinth）的校验不在本文件——本文件只管
// 自更新渠道自身的版本 / URL / 包结构安全。

const (
	maxUpdateUrlLen       = 2048              // URL 长度上限
	maxUpdateAssetNameLen = 256               // 发布资产文件名上限
	maxUpdateZipBytes     = 512 * 1024 * 1024 // 更新包总量上限
	maxUpdateZipEntries   = 20000             // 更新包条目上限
	maxUpdateVersionParts = 32                // 版本号拆段上限
	maxUpdateDescRunes    = 2048              // 更新说明长度上限
)

// allowedUpdateHosts 是默认允许的更新源域名白名单（不含协议与路径）。
// 域名匹配采用"精确或子域"规则，杜绝前缀误配（evil-update.example.com 不算
// example.com 的子域）。
var allowedUpdateHosts = []string{
	"api.github.com",
	"github.com",
	"objects.githubusercontent.com",
	"raw.githubusercontent.com",
	"codeload.github.com",
	"release-assets.githubusercontent.com",
}

// UpdateLimits 是调用方可覆写的限额；零值字段使用默认值。
type UpdateLimits struct {
	UrlLenMax     int
	AssetNameLen  int
	ZipBytesMax   int64
	ZipEntriesMax int
	VersionParts  int
	DescRunesMax  int
}

func (l UpdateLimits) withDefaults() UpdateLimits {
	if l.UrlLenMax <= 0 {
		l.UrlLenMax = maxUpdateUrlLen
	}
	if l.AssetNameLen <= 0 {
		l.AssetNameLen = maxUpdateAssetNameLen
	}
	if l.ZipBytesMax <= 0 {
		l.ZipBytesMax = maxUpdateZipBytes
	}
	if l.ZipEntriesMax <= 0 {
		l.ZipEntriesMax = maxUpdateZipEntries
	}
	if l.VersionParts <= 0 {
		l.VersionParts = maxUpdateVersionParts
	}
	if l.DescRunesMax <= 0 {
		l.DescRunesMax = maxUpdateDescRunes
	}
	return l
}

// UpdateFindings 是校验结论的条目；Severity 用于 UI 分级（error/warn/info）。
type UpdateFindings struct {
	Severity string // "error" / "warn" / "info"
	Code     string
	Message  string
}

// UpdateVerdict 是一次校验的完整结论。
type UpdateVerdict struct {
	OK             bool
	Findings       []UpdateFindings
	Version        string
	VersionValid   bool
	AssetName      string
	HasSingleRoot  bool
	HasLauncherExe bool
	ZipEntryCount  int
	ZipTotalBytes  int64
}
