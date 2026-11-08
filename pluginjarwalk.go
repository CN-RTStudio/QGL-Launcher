package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type pluginJarWalkReasons struct {
	Missing string
	Read    string
	DirLink string
	JarLink string
	JarOpen string
	JarSize string
}

type pluginJarIssue struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type pluginJarWalk struct {
	Dir    string
	Jars   int
	Issues []pluginJarIssue
}

func (w *pluginJarWalk) add(jar, entry, reason, detail string, blocking bool) {
	w.Issues = append(w.Issues, pluginJarIssue{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}

func walkPluginJars(serverDir string, maxSize int64, reasons pluginJarWalkReasons, visit func(name string, archive *zip.ReadCloser)) *pluginJarWalk {
	w := &pluginJarWalk{}
	if serverDir == "" {
		w.add("plugins", "", reasons.Missing, "未配置服务器目录", false)
		return w
	}

	dir := filepath.Join(serverDir, "plugins")
	w.Dir = dir
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		w.add("plugins", "", reasons.Missing, "缺少插件目录", false)
		return w
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		w.add("plugins", "", reasons.Read, err.Error(), true)
		return w
	}
	if link {
		w.add("plugins", "", reasons.DirLink, "插件目录是符号链接或特殊文件", true)
		return w
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		w.add("plugins", "", reasons.Read, "无法读取插件目录", true)
		return w
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		w.Jars++
		path := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			w.add(name, "", reasons.JarOpen, err.Error(), true)
			continue
		}
		if link {
			w.add(name, "", reasons.JarLink, "jar 是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			w.add(name, "", reasons.JarOpen, "jar 无法访问", true)
			continue
		}
		if info.Size() > maxSize {
			w.add(name, "", reasons.JarSize, fmt.Sprintf("jar %d 字节超过上限", info.Size()), false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			w.add(name, "", reasons.JarOpen, "jar 不是合法 zip", true)
			continue
		}
		if visit != nil {
			visit(name, archive)
		}
		archive.Close()
	}

	return w
}
