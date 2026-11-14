package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"

)

func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		// 跳过 PCL 自己的缓存/标记文件（PCL.ini、PCL 文件夹），这些不属于游戏数据
		relLower := strings.ToLower(rel)
		if relLower == "pcl.ini" || strings.HasPrefix(relLower, "pcl\\") || strings.HasPrefix(relLower, "pcl/") {
			return nil
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		dstFile, err := os.Create(target)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}
