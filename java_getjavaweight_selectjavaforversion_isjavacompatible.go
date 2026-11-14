package main

import (
)

func isJavaCompatible(java *JavaEntry, req JavaVersionReq) bool {
	if req.MinMajor > 0 && java.MajorVer < req.MinMajor {
		return false
	}
	if req.MaxMajor > 0 && java.MajorVer > req.MaxMajor {
		return false
	}
	return true
}

// formatMaxVer 格式化最大版本号
