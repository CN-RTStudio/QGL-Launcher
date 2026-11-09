package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func AuditWorldDatapacks(worldDir string) (DatapackAudit, error) {
	audit := DatapackAudit{Dir: filepath.Join(worldDir, "datapacks")}
	info, err := os.Lstat(audit.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return audit, fmt.Errorf("检查数据包目录失败: %v", err)
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, DatapackFinding{
			Name: "datapacks", Reason: datapackReasonSymlink, Blocking: true,
			Detail: "数据包目录是符号链接，拒绝加载其中内容",
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, DatapackFinding{
			Name: "datapacks", Reason: datapackReasonSymlink, Blocking: true,
			Detail: "数据包路径被非目录文件占用",
		})
		return audit, nil
	}
	entries, err := os.ReadDir(audit.Dir)
	if err != nil {
		return audit, fmt.Errorf("读取数据包目录失败: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(audit.Dir, name)
		entryInfo, entryErr := os.Lstat(path)
		if entryErr != nil {
			return audit, fmt.Errorf("检查数据包 %s 失败: %v", name, entryErr)
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, DatapackFinding{
				Name: name, Reason: datapackReasonSymlink, Blocking: true,
				Detail: "数据包是符号链接，拒绝加载外部文件",
			})
			continue
		}
		if entryInfo.IsDir() {
			audit.Packs++
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".zip") {
			audit.Findings = append(audit.Findings, DatapackFinding{
				Name: name, Reason: datapackReasonBadEntry, Blocking: false,
				Detail: "非 .zip 数据包文件被忽略",
			})
			continue
		}
		audit.Packs++
		if audit.Packs > datapackMaxPacks {
			audit.Findings = append(audit.Findings, DatapackFinding{
				Name: name, Reason: datapackReasonTooLarge, Blocking: true,
				Detail: fmt.Sprintf("数据包数量超过 %d", datapackMaxPacks),
			})
			return audit, nil
		}
		if entryInfo.Size() > datapackMaxBytes {
			audit.Findings = append(audit.Findings, DatapackFinding{
				Name: name, Reason: datapackReasonTooLarge, Blocking: true,
				Detail: fmt.Sprintf("数据包超过 %d 字节上限", datapackMaxBytes),
			})
			continue
		}
		reason, detail, blocking := scanDatapackZip(path)
		if reason != datapackReasonOK {
			audit.Findings = append(audit.Findings, DatapackFinding{
				Name: name, Reason: reason, Detail: detail, Blocking: blocking,
			})
		}
	}
	return audit, nil
}
