package main

import (
	"path/filepath"
	"testing"
)

func TestPathWithinRootAcceptsChild(t *testing.T) {
	root := filepath.Clean(filepath.Join("C:", "mc"))
	if !pathWithinRoot(root, filepath.Join(root, "logs", "qgl_install.log")) {
		t.Fatal("子路径应被接受")
	}
}

func TestPathWithinRootRejectsParentEscape(t *testing.T) {
	root := filepath.Clean(filepath.Join("C:", "mc"))
	if pathWithinRoot(root, filepath.Join(root, "..", "evil.log")) {
		t.Fatal("上跳路径必须被拒绝")
	}
}

func TestPathWithinRootRejectsSiblingPrefix(t *testing.T) {
	root := filepath.Clean(filepath.Join("C:", "mc"))
	if pathWithinRoot(root, filepath.Clean(filepath.Join("C:", "mc-evil", "log.txt"))) {
		t.Fatal("同前缀兄弟目录必须被拒绝")
	}
}

func TestPathWithinRootRejectsSelfNameVariant(t *testing.T) {
	root := filepath.Clean(filepath.Join("C:", "mc"))
	if !pathWithinRoot(root, root) {
		t.Fatal("根自身应被接受")
	}
}
