package main

import (
	"crypto/hmac"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func downloadAuthlibJarFromCandidates(jarPath string, candidates []string, expectedSHA256 string) error {
	if len(expectedSHA256) == 0 {
		return fmt.Errorf("缺少 authlib-injector 官方 SHA-256，拒绝下载")
	}
	var lastErr error
	for _, u := range candidates {
		if !isAllowedAuthlibDownloadURL(u) {
			lastErr = fmt.Errorf("下载地址不在可信主机白名单: %s", u)
			continue
		}
		if err := func() error {
			resp, err := httpClient.Get(u)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			// 用 O_EXCL 写同目录临时文件，绝不直接 O_TRUNC 覆盖正在被使用的 jar。
			dir := filepath.Dir(jarPath)
			tmp, err := os.CreateTemp(dir, ".authlib-*.jar.tmp")
			if err != nil {
				return fmt.Errorf("创建临时文件失败: %w", err)
			}
			tmpName := tmp.Name()
			abort := func(cause error) error {
				tmp.Close()
				os.Remove(tmpName)
				return cause
			}
			// 多读 1 字节用于判定是否超限。
			n, err := io.CopyN(tmp, resp.Body, authlibJarMaxBytes+1)
			if err != nil && err != io.EOF {
				return abort(fmt.Errorf("写入文件失败: %w", err))
			}
			if n > authlibJarMaxBytes {
				return abort(fmt.Errorf("authlib-injector 体积超过 %d 字节上限", authlibJarMaxBytes))
			}
			if err := tmp.Close(); err != nil {
				os.Remove(tmpName)
				return fmt.Errorf("关闭临时文件失败: %w", err)
			}

			got, herr := sha256FileHex(tmpName)
			if herr != nil {
				os.Remove(tmpName)
				return fmt.Errorf("计算哈希失败: %w", herr)
			}
			if !hmac.Equal([]byte(got), []byte(expectedSHA256)) {
				os.Remove(tmpName)
				return fmt.Errorf("文件哈希校验失败: 预期 %s, 实际 %s", expectedSHA256, got)
			}
			if err := os.Rename(tmpName, jarPath); err != nil {
				os.Remove(tmpName)
				return fmt.Errorf("替换 jar 失败: %w", err)
			}
			info, _ := os.Stat(jarPath)
			var size int64
			if info != nil {
				size = info.Size()
			}
			if err := saveAuthlibMeta(jarPath, expectedSHA256, size); err != nil {
				// jar 本体已可信，侧车写失败不应致命，下次启动会重新校验/下载。
				removeAuthlibMeta(jarPath)
			}
			return nil
		}(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("下载 authlib-injector 失败: %v", lastErr)
}
