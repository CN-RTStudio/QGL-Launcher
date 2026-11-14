package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
)

func readAPIJSON(resp *http.Response, v interface{}) error {
	body, err := readLimited(resp.Body, apiJSONMaxBytes)
	if err != nil {
		return err
	}
	if int64(len(body)) >= apiJSONMaxBytes {
		return fmt.Errorf("API 响应超过 %d 字节上限", apiJSONMaxBytes)
	}
	return json.Unmarshal(body, v)
}

const (
	maxInstallerJSONBytes int64 = 16 << 20  // 安装器内 JSON 元数据 16 MiB
	maxInstallerLibBytes  int64 = 256 << 20 // 安装器内内嵌库 jar 256 MiB
)
