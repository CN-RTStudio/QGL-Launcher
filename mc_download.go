package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxUnverifiedDownloadBytes 未做哈希校验的下载上限 4 GiB。
// 走这个函数的库 / 安装器体积都远小于此值；正常数据永远碰不到，
// 只有被劫持的镜像持续灌数据炸磁盘时才会触发中止并删除残文件。
const maxUnverifiedDownloadBytes int64 = 4 << 30

// maxMetadataJSONBytes 版本 JSON / 资产索引这类元数据 JSON 的上限。
// 官方文件只有几百 KB ~ 数 MB；它们走通用下载（4 GiB）落地后又被
// os.ReadFile 整体读进内存，被劫持镜像灌一个 GB 级"json"会直接 OOM。
// 单独收窄到 16 MiB，正常数据永远碰不到。
const maxMetadataJSONBytes int64 = 16 << 20

// maxAssetObjectBytes 单个 assets/objects 资源对象上限。
// 内容寻址（路径/URL 即 SHA1），普通贴图/语言文件几 KB，音乐较大也远小于此。
const maxAssetObjectBytes int64 = 256 << 20

var errDownloadTooLarge = errors.New("下载体积超过安全上限")

// cappedReader 读到第 max+1 个字节时返回 errDownloadTooLarge，
// 配合调用方删除残文件，避免恶意端点靠超大响应撑爆磁盘。
type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, errDownloadTooLarge
	}
	return n, err
}

// errLocalFileTooLarge 表示本地文件实际体积超过读取上限。调用方用 errors.Is
// 区分“文件被异常撑大（不应把截断内容当正常配置回写 / 落盘）”与普通读取错误。
var errLocalFileTooLarge = errors.New("本地文件超过安全读取上限")

// localTextConfigMaxBytes 是“读进内存再改写回盘”的纯文本配置（如 options.txt）
// 的默认上限（64MiB）。这类文件正常只有几 KiB，阈值刻意取很宽，只拦被塞成
// GB 级、真能把内存/磁盘撑爆的异常文件（炸磁盘才拦），不跟正常内容过不去。
// 注意它是“读进内存”的上限，不能像下载聚合预算那样取到 TiB 量级。
const localTextConfigMaxBytes int64 = 64 << 20

// readBoundedFile 把本地文件读入内存，但先用 stat 体积、再用 LimitReader+1
// 双保险封顶，防止把磁盘上被塞成 GB 级的"元数据 JSON / 配置"整体读进内存导致 OOM。
//
// 另外两点加固：
//   - 符号链接 / 特殊文件一律拒绝（isSymlinkOrSpecial），避免顺着链接把设备或
//     目录外文件读进来；
//   - 体积超限统一包装成 errLocalFileTooLarge，调用方可 errors.Is 精确识别，
//     而不是靠匹配错误字符串。
func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("readBoundedFile 必须指定正的体积上限")
	}
	if bad, err := isSymlinkOrSpecial(path); err != nil {
		return nil, err
	} else if bad {
		return nil, fmt.Errorf("拒绝读取符号链接或非普通文件: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: 文件 %s 体积 %d 超过上限 %d",
			errLocalFileTooLarge, path, info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: 文件 %s 实际超过上限 %d",
			errLocalFileTooLarge, path, maxBytes)
	}
	return data, nil
}

// downloadContext 返回一个与“下载列表取消信号”绑定的 context。
// 之前 CancelDownloadList 只能在两个文件之间跳出循环，正在传输的大文件
// 仍要等下完才停；把请求挂到这个 context 上后，取消会立刻中断进行中的 HTTP 读取。
// 非下载列表场景（如启动时补全文件）没有取消信号，返回普通 Background context。
func (a *App) downloadContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	a.downloadMutex.Lock()
	ch := a.downloadCancel
	a.downloadMutex.Unlock()
	if ch == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	return a.downloadFileBounded(url, destPath, reportProgress, maxUnverifiedDownloadBytes)
}

// downloadFileBounded 与 downloadFile 相同，但允许调用方按文件类型指定体积上限，
// 让版本 JSON / 资产索引等小元数据不必套用 4 GiB 的宽松上限。
//
// 实际的 HTTP 请求 / 体积双校验 / 流式 sha256 / 原子落盘 / 503 退避重试统一走
// streamVerifiedDownload：这里只保留"已存在跳过""进度上报到前端""错误归一化"
// 三层 App 语义，避免各下载点各自手写请求体。
func (a *App) downloadFileBounded(url string, destPath string, reportProgress bool, maxBytes int64) error {
	if !isHTTPSURL(url) {
		return fmt.Errorf("拒绝不安全的下载 URL（非 HTTPS）: %s", url)
	}
	dir := filepath.Dir(destPath)
	// 统一走 ensurePrivateDir：除创建外还会把已存在但权限过宽（如历史 0755）的目录
	// 收敛到 0700。所有 downloadFile/downloadFileBounded/downloadVerifiedFile 都汇聚到这里，
	// 各调用点不再各自 MkdirAll。
	if err := ensurePrivateDir(dir); err != nil {
		return fmt.Errorf("创建目录失败 %s: %w", dir, err)
	}
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}
	ctx, cancelReq := a.downloadContext()
	defer cancelReq()
	opts := secureDownloadOptions{
		MaxBytes:  maxBytes,
		Attempts:  3,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:    safeHTTPClient(),
	}
	if reportProgress {
		opts.Progress = func(received, total int64) {
			a.emitProgress("downloading", filepath.Base(destPath), received, total)
		}
	}
	if _, err := streamVerifiedDownload(ctx, url, destPath, opts); err != nil {
		// 下载台账：传输失败留痕（无论是否有哈希期望，失败都要可审计）。
		a.RecordDownloadEntry(url, ledgerHostOf(url), filepath.Base(destPath), "", "", LedgerStatusFailed, -1)
		if errors.Is(err, errSecureDownloadTooLarge) {
			return fmt.Errorf("下载失败 %s: %w", url, errDownloadTooLarge)
		}
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	return nil
}

// downloadVerifiedFile 下载并校验官方 SHA1；缓存命中走侧车摘要链
// （UMFS -> SHA512 -> SHA1）快速复用，新下载落盘则以官方 SHA1 为唯一信任锚
// 校验通过后再补写 UMFS/SHA512 侧车；校验失败删除重下一次。
func (a *App) downloadVerifiedFile(url string, destPath string, expectedSHA1 string, reportProgress bool) error {
	if expectedSHA1 == "" {
		return a.downloadFile(url, destPath, reportProgress)
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA1))
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 && a.verifyCachedFile(destPath, expected) {
		return nil
	}
	os.Remove(destPath)
	removeCachedFileMeta(destPath)
	if err := a.downloadFile(url, destPath, reportProgress); err != nil {
		return err
	}
	// 外部协议摘要（Mojang SHA1）保持原算法，是首次下载唯一的权威校验。
	if !a.checkFileHash(destPath, expected) {
		os.Remove(destPath)
		removeCachedFileMeta(destPath)
		// 下载台账：官方 SHA1 校验不通过 = 潜在供应链异常，critical 留痕。
		a.RecordDownloadEntry(url, ledgerHostOf(url), filepath.Base(destPath), "sha1", expected, LedgerStatusMismatch, -1)
		return fmt.Errorf("SHA1 校验失败: %s", destPath)
	}
	// 官方 SHA1 已通过：本地缓存摘要用 bool-hybrid-array 生态的 UMFS 优先记录。
	if err := a.saveCachedFileMeta(destPath, expected); err != nil {
		a.writeLog("缓存元数据写入失败（不影响完整性）: %s: %v", destPath, err)
	}
	// 下载台账：Mojang SHA1 校验通过后记 ok（哈希保持原算法 sha1）。
	a.RecordDownloadEntry(url, ledgerHostOf(url), filepath.Base(destPath), "sha1", expected, LedgerStatusOK, -1)
	return nil
}
