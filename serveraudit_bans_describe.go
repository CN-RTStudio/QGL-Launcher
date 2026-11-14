package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func (a *BanEnforcementAudit) Describe() string {
	return describeFileDetail("封禁与管理员名单未发现冲突", a.Findings, 12)
}

type sbeBan struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}

func sbeLoad(serverDir, name string, a *BanEnforcementAudit) ([]sbeBan, bool) {
	path := filepath.Join(serverDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(name, sbeLink, "名单文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, sbeMaxFile)
	if err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	var list []sbeBan
	if err := json.Unmarshal(data, &list); err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	return list, true
}

func sbeOpNames(serverDir string) map[string]bool {
	data, err := readBoundedFile(filepath.Join(serverDir, "ops.json"), sbeMaxFile)
	if err != nil {
		return map[string]bool{}
	}
	var ops []sbeBan
	if err := json.Unmarshal(data, &ops); err != nil {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(ops))
	for _, op := range ops {
		if key := strings.ToLower(strings.TrimSpace(op.UUID)); key != "" {
			out[key] = true
		}
	}
	return out
}
