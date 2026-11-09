package main

import (
	"errors"
	"io"
)

const maxUnverifiedDownloadBytes int64 = 4 << 30
const maxMetadataJSONBytes int64 = 16 << 20
const maxAssetObjectBytes int64 = 256 << 20

var errDownloadTooLarge = errors.New("下载体积超过安全上限")

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

var errLocalFileTooLarge = errors.New("本地文件超过安全读取上限")

const localTextConfigMaxBytes int64 = 64 << 20
