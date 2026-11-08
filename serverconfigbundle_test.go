package main

import (
	"strings"
	"testing"
	"time"
)

func baseBundle() ServerConfigBundle {
	return ServerConfigBundle{
		Version:    serverConfigBundleVersion,
		Name:       "生存服",
		MCVersion:  "1.21.4",
		Port:       25565,
		MinMemory:  512,
		MaxMemory:  4096,
		OnlineMode: true,
		CreatedAt:  time.Now().UnixMilli(),
	}
}

func TestNormalizeServerConfigBundleAcceptsValid(t *testing.T) {
	out, err := normalizeServerConfigBundle(baseBundle(), time.Now())
	if err != nil {
		t.Fatalf("合法配置被拒: %v", err)
	}
	if out.Version != serverConfigBundleVersion || out.Name != "生存服" {
		t.Fatalf("归一化结果异常: %+v", out)
	}
}

func TestNormalizeServerConfigBundleRejectsBadFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ServerConfigBundle)
	}{
		{"空名称", func(b *ServerConfigBundle) { b.Name = "  " }},
		{"名称过长", func(b *ServerConfigBundle) { b.Name = strings.Repeat("服", serverConfigBundleNameRune+1) }},
		{"名称含分隔符", func(b *ServerConfigBundle) { b.Name = "../evil" }},
		{"版本空", func(b *ServerConfigBundle) { b.MCVersion = "" }},
		{"版本穿越", func(b *ServerConfigBundle) { b.MCVersion = "../1.21" }},
		{"端口越界", func(b *ServerConfigBundle) { b.Port = 70000 }},
		{"内存越界", func(b *ServerConfigBundle) { b.MaxMemory = maxMemoryMB + 1 }},
		{"内存倒挂", func(b *ServerConfigBundle) { b.MinMemory = 4096; b.MaxMemory = 1024 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := baseBundle()
			tc.mutate(&bundle)
			if _, err := normalizeServerConfigBundle(bundle, time.Now()); err == nil {
				t.Fatalf("非法配置未被拒绝: %+v", bundle)
			}
		})
	}
}

func TestNormalizeServerConfigBundleRepairsStamp(t *testing.T) {
	bundle := baseBundle()
	bundle.CreatedAt = -1
	out, err := normalizeServerConfigBundle(bundle, time.Now())
	if err != nil {
		t.Fatalf("归一化失败: %v", err)
	}
	if out.CreatedAt <= 0 {
		t.Fatalf("时间戳未修复: %d", out.CreatedAt)
	}
}

func TestMarshalParseServerConfigBundleRoundTrip(t *testing.T) {
	cfg := ServerConfig{
		Name:       "创造服",
		Version:    "1.20.1",
		Port:       25566,
		MinMemory:  1024,
		MaxMemory:  8192,
		OnlineMode: false,
	}
	payload, err := MarshalServerConfigBundle(cfg, time.Now())
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	bundle, err := ParseServerConfigBundle(payload)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if bundle.Name != cfg.Name || bundle.Port != cfg.Port || bundle.OnlineMode != cfg.OnlineMode {
		t.Fatalf("往返字段不一致: %+v", bundle)
	}
	if !strings.Contains(bundle.Describe(), "创造服") {
		t.Fatalf("描述缺少名称: %s", bundle.Describe())
	}
}

func TestParseServerConfigBundleRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"空", ""},
		{"非JSON", "{not json"},
		{"版本不符", `{"version":9,"name":"x","mcVersion":"1.21","port":25565,"minMemory":512,"maxMemory":1024}`},
		{"端口越界", `{"version":1,"name":"x","mcVersion":"1.21","port":0,"minMemory":512,"maxMemory":1024}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseServerConfigBundle([]byte(tc.data)); err == nil {
				t.Fatalf("非法输入未被拒绝: %s", tc.data)
			}
		})
	}
}

func TestParseServerConfigBundleRejectsOversize(t *testing.T) {
	huge := strings.Repeat("a", serverConfigBundleMaxBytes+1)
	if _, err := ParseServerConfigBundle([]byte(huge)); err == nil {
		t.Fatalf("超长输入未被拒绝")
	}
}
