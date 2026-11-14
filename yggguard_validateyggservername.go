package main

import (
	"strings"
)

func validateYggServerName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if len(name) > maxYggServerNameLen {
		return "", false
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return "", false
		}
	}
	return name, true
}

// describeYggReject 把角色资料拒绝原因码转成中文说明。
func describeYggReject(why string) string {
	return rejectReasonText(why, "外置登录数据未通过校验", describeYggRejectTexts)
}
