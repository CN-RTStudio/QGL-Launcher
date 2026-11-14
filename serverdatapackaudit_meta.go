package main

import (
	"encoding/json"
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
