package main

import "os"

type regularFileState struct {
	Exists bool
	Size   int64
	Reason string
}

func inspectRegularFile(path string) regularFileState {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return regularFileState{Reason: "missing"}
		}
		return regularFileState{Reason: "stat-error"}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return regularFileState{Exists: true, Size: info.Size(), Reason: "symlink"}
	}
	if !info.Mode().IsRegular() {
		return regularFileState{Exists: true, Size: info.Size(), Reason: "special"}
	}
	return regularFileState{Exists: true, Size: info.Size(), Reason: "ok"}
}

func (s regularFileState) trustable() bool {
	return s.Reason == "ok"
}

func describeUntrustedFile(s regularFileState, path string) string {
	switch s.Reason {
	case "symlink":
		return "本地目标是指向别处的符号链接，拒绝直接信任: " + path
	case "special":
		return "本地目标不是普通文件，拒绝直接信任: " + path
	}
	return ""
}
