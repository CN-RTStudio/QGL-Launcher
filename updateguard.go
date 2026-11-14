package main

import ()

const (
	maxUpdateUrlLen       = 2048              // URL 长度上限
	maxUpdateAssetNameLen = 256               // 发布资产文件名上限
	maxUpdateZipBytes     = 512 * 1024 * 1024 // 更新包总量上限
	maxUpdateZipEntries   = 20000             // 更新包条目上限
	maxUpdateVersionParts = 32                // 版本号拆段上限
	maxUpdateDescRunes    = 2048              // 更新说明长度上限
)

var allowedUpdateHosts = []string{
	"api.github.com",
	"github.com",
	"objects.githubusercontent.com",
	"raw.githubusercontent.com",
	"codeload.github.com",
	"release-assets.githubusercontent.com",
}

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
