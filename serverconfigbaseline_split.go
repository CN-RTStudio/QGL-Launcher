package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func hashBaselineFiles(serverDir string, audit *BaselineAudit) (map[string]string, error) {
	hashes := make(map[string]string, len(baselineFileNames))
	for _, name := range baselineFileNames {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonUnreadable, Detail: "无法读取文件属性", Blocking: false,
			})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > baselineMaxBytes {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonUnreadable,
				Detail: "文件是符号链接、特殊文件或超过体积上限，跳过基线比对", Blocking: false,
			})
			continue
		}
		sum, err := umfsFile(path)
		if err != nil {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonUnreadable, Detail: "计算摘要失败", Blocking: false,
			})
			continue
		}
		hashes[name] = sum
	}
	return hashes, nil
}

func compareBaseline(audit *BaselineAudit, previous, current map[string]string) {
	for name, oldSum := range previous {
		currentSum, ok := current[name]
		if !ok {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonRemoved,
				Detail: "上次记录存在的配置文件已消失", Blocking: false,
			})
			continue
		}
		if oldSum != currentSum {
			audit.Findings = append(audit.Findings, BaselineFinding{
				File: name, Reason: baselineReasonModified,
				Detail: fmt.Sprintf("摘要由 %s 变为 %s", shortSum(oldSum), shortSum(currentSum)), Blocking: false,
			})
		}
	}
	for name := range current {
		if _, ok := previous[name]; ok {
			continue
		}
		audit.Findings = append(audit.Findings, BaselineFinding{
			File: name, Reason: baselineReasonAdded,
			Detail: "基线中没有该配置文件，已纳入本次基线", Blocking: false,
		})
	}
}
