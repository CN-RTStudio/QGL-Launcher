package main

import (
	"encoding/hex"
	"testing"
)

// umfsGoldenVectors 是与 bool-hybrid-array 上游
// （bool_hybrid_array/core.py，UltraMersenneFractalSponge，bitn=256）逐字节对齐的
// 跨语言黄金向量，用于防止本地 Go 移植再次与 Python 生态漂移。向量由上游 core.py
// 的 UMFS 原始源码（M=2^2281-1，分块 absorb、fold/squeeze 的真实运算优先级）直接执行生成。
func umfsGoldenInputs() map[string][]byte {
	chunk := make([]byte, 0, 300)
	seg := []byte("OpenQGL-UMFS-cross-vector-0123456789-")
	for len(chunk) < 300 {
		chunk = append(chunk, seg...)
	}
	chunk = chunk[:300]

	bin256 := make([]byte, 256)
	for i := 0; i < 256; i++ {
		bin256[i] = byte(i)
	}

	// 多块 absorb 边界：step=n//bitlen(n) 会把这些长度切成 6~8 块，
	// 用来对拍上游“单次条件减法”与移植版模归约在反复更新 c 时是否仍数值等价。
	bin64 := make([]byte, 64)
	for i := 0; i < 64; i++ {
		bin64[i] = byte(i)
	}
	bin255 := make([]byte, 255)
	for i := 0; i < 255; i++ {
		bin255[i] = byte(i % 256)
	}
	rep256 := make([]byte, 0, 256)
	for len(rep256) < 256 {
		rep256 = append(rep256, 'A', 'B', 'C', 'D')
	}

	return map[string][]byte{
		"empty":     {},
		"a":         []byte("a"),
		"abc":       []byte("abc"),
		"hello":     []byte("hello world"),
		"chunk300":  chunk,
		"bin256":    bin256,
		"len16":     []byte("0123456789abcdef"),
		"len64":     bin64,
		"len255":    bin255,
		"len256rep": rep256,
	}
}

func TestUMFSGoldenVectors(t *testing.T) {
	want := map[string]string{
		"empty":     "042624191ad60cc3b2f890c34d1a4a0e14bb42b6333a50430b369a0698a34f95",
		"a":         "aafef5a5ed61b96cd3a6d4d0308c98f7119a5937e95a6fb1aac25f708a789964",
		"abc":       "ed9ca21778317f62b5afb54a731b2c17c23deb7913c30d937171dde3cbce0049",
		"hello":     "6c04e0dda3355a22ddec11151d3535f55ab5fafc276cc28acaacd35e24840cb5",
		"chunk300":  "335a02585f90222a17dc2d613b4513623f2529c6d809135b0acd91f13687f2fb",
		"bin256":    "e5149a8224e057ad0ee83bda28b53c1c6a5075aae4a1ffd060cd8cdd08312504",
		"len16":     "a280aaf1d54d92a4f3c149ff5ac5deec39da28fb51c389cfebd3591c82478e9d",
		"len64":     "abfa9097fa24b5f3063a6435d8acb85c5f9a0d196e122d399945236a0e616dc2",
		"len255":    "f855ae23f4078f0a803d7f4e6a3b89f09197783403dc338665c5398157051878",
		"len256rep": "c5bc51aefefa13f02f6d1301b436a7d504542d3ef54f7ab89963a8ab5c565739",
	}
	for name, in := range umfsGoldenInputs() {
		if got := NewUMFS(in).HexDigest(256); got != want[name] {
			t.Errorf("UMFS(%s) = %s, want %s（与 bool-hybrid-array 上游不一致）", name, got, want[name])
		}
	}
}

// TestUMFSStreamEqualsWhole 验证 hash.Hash 流式分块写入与整段一次性吸收结果一致。
func TestUMFSStreamEqualsWhole(t *testing.T) {
	inputs := umfsGoldenInputs()
	for name, in := range inputs {
		whole := NewUMFS(in).HexDigest(256)

		h := NewUMFSHash()
		// 故意用不均匀的切分（含 1 字节边界）多次 Write。
		stride := []int{1, 7, 64, 300}
		si, off := 0, 0
		for off < len(in) {
			n := stride[si%len(stride)]
			end := off + n
			if end > len(in) {
				end = len(in)
			}
			if _, err := h.Write(in[off:end]); err != nil {
				t.Fatalf("%s: write error %v", name, err)
			}
			off = end
			si++
		}
		streamed := hex.EncodeToString(h.Sum(nil))
		if streamed != whole {
			t.Errorf("%s: streamed=%s whole=%s，流式与整段结果不一致", name, streamed, whole)
		}
	}
}
