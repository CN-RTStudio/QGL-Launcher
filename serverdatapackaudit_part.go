package main

import (
	"encoding/json"
	"strings"
)

func packCheckMeta(audit *DataPackAudit, name string, data []byte) {
	var meta packMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		audit.add(name, dpReasonInvalidMcmeta, "pack.mcmeta 不是合法 JSON", false)
		return
	}
	if meta.Pack.PackFormat <= 0 || meta.Pack.PackFormat > 128 {
		audit.add(name, dpReasonInvalidMcmeta, "pack_format 越界或缺失", false)
	}
	desc, ok := packDescription(meta.Pack.Description)
	if !ok {
		audit.add(name, dpReasonBadDescription, "description 结构不受支持", false)
		return
	}
	if len(desc) > dpMaxDescLen {
		audit.add(name, dpReasonBadDescription, "description 超长", false)
	}
	if packHasControl(desc) {
		audit.add(name, dpReasonBadDescription, "description 含控制字符", false)
	}
}

func packHasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch < 0x20 && ch != '\t' && ch != '\n' {
			return true
		}
		if ch == 0x7f {
			return true
		}
	}
	return false
}

func packEntryUnsafe(name string) bool {
	if name == "" {
		return true
	}
	if strings.Contains(name, "\x00") || strings.Contains(name, `\`) {
		return true
	}
	if strings.HasPrefix(name, "/") {
		return true
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
