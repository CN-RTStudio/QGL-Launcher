package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

)

func httpGetBytes(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 皮肤最大 4MB，防止异常响应撑爆内存
}

// extractFacePNG 从 64x64（或 64x32）皮肤图中裁剪脸部并叠加帽子层，输出 64x64 PNG
