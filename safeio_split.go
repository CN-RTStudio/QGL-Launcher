package main

import (
	"encoding/json"
	"fmt"
)

func secureWritePrivateFile(path string, data []byte) error {
	return secureWriteFile(path, data, privateFilePerm)
}

// defaultPrivateJSONWriteMaxBytes 是私有 JSON 写入的默认体量上限，取 64MiB 这种极宽值：
// 只拦截序列化结果被撑到炸磁盘量级的异常配置，正常令牌 / 版本 JSON 是 KB 量级，碰不到。
var defaultPrivateJSONWriteMaxBytes int64 = 64 << 20

// writePrivateJSON 把任意结构序列化为缩进 JSON，再走原子私有写（使用 64MiB 默认上限）。
func writePrivateJSON(path string, v interface{}) error {
	return writePrivateJSONBounded(path, v, 0)
}

// writePrivateJSONBounded 把结构序列化为缩进 JSON，先核实体量再走 0600 原子私有写。
// maxBytes<=0 时取默认 64MiB；空结果、超上限、序列化失败都不落盘并返回错误（超限可用
// errors.Is 识别为 errLocalFileTooLarge），避免吞掉 Marshal/WriteFile 错误后留下半截或巨型文件。
func writePrivateJSONBounded(path string, v interface{}, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = defaultPrivateJSONWriteMaxBytes
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("序列化 JSON 为空，拒绝写入 %s", path)
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("%w: %s 序列化后 %d 字节超过上限 %d", errLocalFileTooLarge, path, len(data), maxBytes)
	}
	return secureWritePrivateFile(path, data)
}
