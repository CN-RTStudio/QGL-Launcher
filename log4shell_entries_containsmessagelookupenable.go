package main

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
)

func containsMessageLookupEnable(lowerText string) bool {
	if strings.Contains(lowerText, "%m{lookups}") || strings.Contains(lowerText, "%msg{lookups}") ||
		strings.Contains(lowerText, "%message{lookups}") {
		return true
	}
	// <PatternLayout ... lookups="true"> / isLookups=true 等属性写法。
	if strings.Contains(lowerText, "lookups") && strings.Contains(lowerText, "true") {
		return true
	}
	return false
}

func inspectLog4jClass(rep *Log4ShellReport, f *zip.File, entry string, spent int) int {
	rc, err := f.Open()
	if err != nil {
		return 0
	}
	defer rc.Close()

	left := log4jClassBytesCap - spent
	limit := int64(log4jClassCap)
	if int64(left) < limit {
		limit = int64(left)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return 0
	}
	texts := classConstantPoolUTF8(data)
	if texts == nil {
		return 0 // 魔数不符 / 结构截断，跳过
	}

	hasNaming := false
	hasJndiUrl := false
	hasLookupClassRef := false
	for _, s := range texts {
		ls := strings.ToLower(s)
		if !hasNaming && (strings.Contains(ls, "javax/naming/initialcontext") ||
			strings.Contains(ls, "javax/naming/context")) {
			hasNaming = true
		}
		if !hasJndiUrl {
			for _, scheme := range jndiUrlSchemes {
				if strings.Contains(ls, scheme) {
					hasJndiUrl = true
					break
				}
			}
		}
		if !hasLookupClassRef && strings.Contains(ls, "log4j/core/lookup/") {
			hasLookupClassRef = true
		}
	}
	if hasNaming && hasJndiUrl {
		rep.addOnce(JarSeverityWarn, "jndi-outbound-class", entry,
			"class 常量池同时引用 javax.naming 与 ldap/rmi/dns 子协议，具备主动外联 JNDI（远程类加载）能力")
	}
	if hasLookupClassRef && hasJndiUrl {
		rep.addOnce(JarSeverityWarn, "log4j-jndi-url", entry,
			"class 常量池出现 log4j lookup 引用与 JNDI 子协议 URL，需确认是否为受影响 log4j 版本")
	}
	return len(data)
}

func scanLog4ShellNested(rep *Log4ShellReport, f *zip.File, display string, depth int,
	nestedCount *int, nestedBytes *int) {
	if depth >= log4jNestedDepth {
		rep.limitNested = true
		return
	}
	if *nestedCount >= log4jMaxNested || *nestedBytes >= log4jNestedBytesCap {
		rep.limitNested = true
		return
	}
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	left := log4jNestedBytesCap - *nestedBytes
	limit := int64(log4jPerNestedCap)
	if int64(left) < limit {
		limit = int64(left)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return
	}
	childZr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// 非合法 zip（损坏 / 伪装）不致命：jarscan 已有 nested-unreadable 告警。
		return
	}
	*nestedCount++
	*nestedBytes += len(data)
	scanLog4ShellInto(rep, childZr, depth+1, display+"!/", nestedCount, nestedBytes)
}
