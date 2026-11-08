package main

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
)

// 解压覆写文件时的大小上限，防止 zip bomb（高压缩比小文件膨胀占满磁盘）。
const (
	maxOverridesEntryBytes int64 = 8 << 30  // 单个文件最多 8 GiB（正常整合包条目远小于此，只有解压炸弹才会触发）
	maxOverridesTotalBytes int64 = 256 << 30 // 全部覆写文件合计最多 256 GiB（只在明显炸磁盘时中止）
	maxMrpackDownloadBytes  int64 = 8 << 30  // 整合包本体最多 8 GiB，与单文件上限一致
	maxMrpackManifestBytes  int64 = 16 << 20 // modrinth.index.json 最多 16 MiB（清单只是文件列表，正常远小于此）
	maxOverridesEntries     = 100000        // 覆写条目数上限，防海量空文件耗尽 inode / 拖慢解压
)

// unsafeEntryMode 拒绝在覆写区落地的特殊文件类型：符号链接 / 设备 / 管道 / 套接字。
// zip 里这类条目本不该出现在整合包，放行符号链接还可能被利用做链接逃逸或诱导覆盖。
const unsafeEntryMode = os.ModeSymlink | os.ModeDevice | os.ModeNamedPipe | os.ModeSocket

// ===== Modrinth 整合包 API 结构体 =====

type ModpackSearchResult = ModSearchResult
type ModpackSearchResponse = ModSearchResponse

type ModrinthModpackManifest struct {
	FormatVersion int                   `json:"formatVersion"`
	Game          string                `json:"game"`
	VersionID     string                `json:"versionId"`
	Name          string                `json:"name"`
	Files         []ModrinthModpackFile `json:"files"`
	Dependencies  map[string]string     `json:"dependencies"`
}

type ModrinthModpackFile struct {
	Path      string            `json:"path"`
	Hashes    map[string]string `json:"hashes"`
	Downloads []string          `json:"downloads"`
	FileSize  int64             `json:"fileSize"`
	// Env 是 Modrinth 规范的端侧声明 {"client","server"} = required|optional|unsupported。
	// 客户端安装时只选取 client != unsupported 的文件；缺失视为两侧都需要。
	Env map[string]string `json:"env"`
}

// sha1File 计算文件 SHA1（仅作 sha512 缺失时的回退）
func sha1File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ===== UMFS 本地完整性缓存 =====
// 首次下载用 Modrinth 给的 sha512 验完后，把文件的 UMFS-256 指纹缓存到本地；
// 以后再遇到同一文件（用 Modrinth 的 sha512/sha1 当 key）就优先比对 UMFS。
// 优先级：缓存 UMFS → manifest sha512 → manifest sha1。

type umfsCache struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

var globalUMFSCache *umfsCache
var umfsCacheOnce sync.Once

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

func (c *umfsCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	return v, ok
}

func (c *umfsCache) set(key, umfsHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = umfsHex
	// 原子私有写（含 0700 目录收敛、0600、fsync/rename、拒符号链接），替换原先
	// 裸 Marshal+MkdirAll+WriteFile；失败仅表示本次指纹未持久化，不影响当次校验结果。
	_ = writePrivateJSON(c.path, c.data)
}

// verifyDownloadedFile 按优先级校验：缓存 UMFS → sha512 → sha1。
// 任一可信算法通过后会把 UMFS 指纹写回缓存。
