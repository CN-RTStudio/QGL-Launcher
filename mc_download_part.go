package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

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
