package main

import (
	"strings"
)

func getUMFSCache(cachePath string) *umfsCache {
	umfsCacheOnce.Do(func() {
		globalUMFSCache = &umfsCache{path: cachePath, data: map[string]string{}}
		// 缓存是本地文本 JSON，走有界读取（默认 64MiB）：文件缺失 / 损坏 / 被改成
		// 超大体积都从空缓存起步，绝不整体读进内存，也不阻断后续下载。
		if err := readLocalJSONBounded(cachePath, &globalUMFSCache.data, 0, "umfs完整性缓存"); err != nil {
			globalUMFSCache.data = map[string]string{}
		}
	})
	return globalUMFSCache
}

func (c *umfsCache) keyFor(hashes map[string]string) string {
	if v := strings.ToLower(strings.TrimSpace(hashes["sha512"])); v != "" {
		return "sha512:" + v
	}
	if v := strings.ToLower(strings.TrimSpace(hashes["sha1"])); v != "" {
		return "sha1:" + v
	}
	return ""
}
