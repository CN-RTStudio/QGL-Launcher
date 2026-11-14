package main

import (
	"fmt"
	"strings"
)

func (a PlayerDataAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}

func (a PlayerDataAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("玩家数据目录共 %d 个文件，未发现异常", a.Files)
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s/%s: %s", finding.Dir, finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}
