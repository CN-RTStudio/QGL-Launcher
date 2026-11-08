package main

// configwatch：关键配置指纹监控。
//
// 场景：攻击者可以趁启动器不运行时改 instance.json / options.txt /
// launcher_profiles.json，把 javaPath 换成本地恶意程序，再恢复原文件内容
// 掩盖痕迹（文件时间戳可伪造，但内容指纹不能伪造——除非篡改者知道指纹算法
// 并重算）。本模块：
//   - 对给定文件列表流式计算 UMFS-256 指纹（本地用途哈希统一走 bool-hybrid-
//     array 生态的 UMFS，不引入额外依赖）；
//   - 与上次记录的指纹对比，输出每个文件的 changed/unchanged/new/missing；
//   - 指纹记录本身用 JSON 保存，记录文件大小有界、行数有界；
//   - 纯函数 + 读写辅助，不改动被监控文件。

import (
	"encoding/json"
	"os"
	"strings"
)

// WatchLimits 指纹记录文件的量化边界。
type WatchLimits struct {
	MaxRecordBytes int
	MaxFiles       int
}

func defaultWatchLimits() WatchLimits {
	return WatchLimits{MaxRecordBytes: 1 << 20, MaxFiles: 200}
}

// fileFingerprint 单个文件的指纹快照。
type fileFingerprint struct {
	Path string `json:"path"`
	UMFS string `json:"umfs"`
}

// fingerprintRecord 全部受监控文件的指纹快照。
type fingerprintRecord struct {
	Files []fileFingerprint `json:"files"`
}

// watchDiff 一次对比的结果。
type watchDiff struct {
	OK      bool
	Reason  string
	Changed []string // 内容变化
	Missing []string // 文件消失
	New     []string // 新出现的文件
}

// recordFingerprint 计算一批文件的 UMFS 指纹（流式读文件）。
func recordFingerprint(paths []string, lim WatchLimits) (fingerprintRecord, error) {
	if lim.MaxFiles == 0 {
		lim = defaultWatchLimits()
	}
	rec := fingerprintRecord{}
	if len(paths) > lim.MaxFiles {
		return rec, errText("watch-files-overflow")
	}
	for _, p := range paths {
		h, err := umfsFile(p)
		if err != nil {
			// 文件缺失也记录一条空指纹，缺失本身在 diff 阶段报告
			rec.Files = append(rec.Files, fileFingerprint{Path: p, UMFS: ""})
			continue
		}
		rec.Files = append(rec.Files, fileFingerprint{Path: p, UMFS: h})
	}
	return rec, nil
}

// saveFingerprintRecord 把指纹快照写成 JSON（有界写入，不覆盖被监控文件）。
func saveFingerprintRecord(path string, rec fingerprintRecord, lim WatchLimits) error {
	if lim.MaxRecordBytes == 0 {
		lim = defaultWatchLimits()
	}
	raw, err := json.MarshalIndent(rec, "", " ")
	if err != nil {
		return err
	}
	if len(raw) > lim.MaxRecordBytes {
		return errText("watch-record-too-large")
	}
	return secureWriteFile(path, raw, 0o600)
}

// loadFingerprintRecord 读取上次指纹快照。
func loadFingerprintRecord(path string, lim WatchLimits) (fingerprintRecord, error) {
	if lim.MaxRecordBytes == 0 {
		lim = defaultWatchLimits()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fingerprintRecord{}, err
	}
	if len(raw) > lim.MaxRecordBytes {
		return fingerprintRecord{}, errText("watch-record-too-large")
	}
	var rec fingerprintRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fingerprintRecord{}, err
	}
	if len(rec.Files) > lim.MaxFiles {
		return fingerprintRecord{}, errText("watch-record-overflow")
	}
	return rec, nil
}

// diffFingerprints 对比新旧指纹。以新快照为准：旧快照里没有的路径算 new，
// 新快照里 UMFS 为空算 missing，两侧都有且指纹不同算 changed。
func diffFingerprints(prev, cur fingerprintRecord) watchDiff {
	d := watchDiff{OK: true}
	prevMap := map[string]string{}
	for _, f := range prev.Files {
		prevMap[f.Path] = f.UMFS
	}
	curMap := map[string]string{}
	for _, f := range cur.Files {
		curMap[f.Path] = f.UMFS
	}
	for path, h := range curMap {
		if h == "" {
			d.Missing = append(d.Missing, path)
			continue
		}
		old, seen := prevMap[path]
		if !seen {
			d.New = append(d.New, path)
			continue
		}
		if old != h {
			d.Changed = append(d.Changed, path)
		}
	}
	sortStrings(d.Changed)
	sortStrings(d.Missing)
	sortStrings(d.New)
	if len(d.Changed) > 0 || len(d.Missing) > 0 {
		d.OK = false
	}
	if len(d.Changed) > 0 {
		d.Reason = "changed:" + strings.Join(d.Changed, ",")
	} else if len(d.Missing) > 0 {
		d.Reason = "missing:" + strings.Join(d.Missing, ",")
	}
	return d
}

// SummarizeWatchDiff 压成一行。
func SummarizeWatchDiff(d watchDiff) string {
	if d.OK {
		return "configwatch ok changed=" + itoaSafe(len(d.Changed)) + " missing=" + itoaSafe(len(d.Missing)) + " new=" + itoaSafe(len(d.New))
	}
	return "configwatch bad " + d.Reason
}
