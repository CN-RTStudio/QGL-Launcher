package main

import (
	"sort"
)

func (p *serverProperties) Keys() []string {
	seen := map[string]bool{}
	var keys []string
	for _, ln := range p.lines {
		if ln.isPair && !seen[ln.key] {
			seen[ln.key] = true
			keys = append(keys, ln.key)
		}
	}
	sort.Strings(keys)
	return keys
}

// updateServerProperty 以保序方式更新 server.properties 中的单个键并原子落盘。
// valueValidator 非空时用于校验待写入的值（防配置注入）；文件不存在时返回错误。
