package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func stAuditFile(audit *StatsAudit, dir, name, path string, info os.FileInfo) {
	audit.Files++
	audit.Bytes += info.Size()
	if !stFilePattern.MatchString(name) {
		audit.add(dir, name, stReasonBadFileName, "文件名不是标准 UUID", false)
	}
	if info.Size() > stMaxFileBytes {
		audit.add(dir, name, stReasonTooLarge, fmt.Sprintf("统计文件 %d 字节", info.Size()), true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(dir, name, stReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
	}
	raw, err := readBoundedFile(path, stMaxFileBytes)
	if err != nil {
		audit.add(dir, name, stReasonUnreadable, err.Error(), false)
		return
	}
	if depth := stJSONDepth(raw); depth > stMaxDepth {
		audit.add(dir, name, stReasonDeepNesting, fmt.Sprintf("嵌套深度 %d", depth), true)
		return
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
			audit.add(dir, name, stReasonNotObject, "统计文件顶层不是对象", false)
			return
		}
		audit.add(dir, name, stReasonMalformedJSON, "统计文件无法解析", false)
		return
	}
	for _, key := range stDuplicateKeys(raw) {
		audit.add(dir, name, stReasonDuplicateKey, "重复键 "+key, false)
	}
	if len(decoded) == 0 {
		audit.add(dir, name, stReasonNotObject, "统计文件内容为空", false)
	}
}
