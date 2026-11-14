package main

import (
	"encoding/json"
	"fmt"
	"os"
)

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

func readBaselineStore(path string) (*baselineStore, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > baselineMaxBytes {
		return nil, fmt.Errorf("基线文件不是可信普通文件")
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, err
	}
	var store baselineStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	if store.Version != baselineVersion || store.Files == nil {
		return nil, fmt.Errorf("基线版本不支持")
	}
	return &store, nil
}
