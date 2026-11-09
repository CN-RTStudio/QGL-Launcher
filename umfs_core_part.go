package main

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"os"
)

func (u *UMFS) HexDigest(bitn int) string {
	u.flushPending()
	if bitn <= 0 || bitn > 4562 {
		bitn = 256
	}

	len3 := umfsPow(big.NewInt(int64(u.totalLen)), umfs3)
	u.r = new(big.Int).Xor(u.r, len3)
	u.c = new(big.Int).Mod(new(big.Int).Add(u.c, new(big.Int).Mul(len3, u.r)), umfsM)

	foldVal := u.foldRecursive(u.dataPool)
	u.r = new(big.Int).Mod(new(big.Int).Xor(u.r, foldVal), umfsM)

	for i := 0; i < 10; i++ {
		u.r = tenthOrderMapping(u.r)
		u.c = tenthOrderMapping(u.c)
		r3 := umfsPow(u.r, umfs3)
		c3 := umfsPow(u.c, umfs3)
		// Python：cross = (r3 ^ c3 + r*c) % M，'+' 优先级高于 '^'，
		// 真实含义是 r3 ^ (c3 + r*c)，旧实现误写成 (r3^c3)+(r*c)。
		cross := new(big.Int).Mod(
			new(big.Int).Xor(r3, new(big.Int).Add(c3, new(big.Int).Mul(u.r, u.c))),
			umfsM)
		oldR := new(big.Int).Set(u.r)
		u.r = new(big.Int).Mod(cross, umfsM)
		u.c = new(big.Int).Mod(new(big.Int).Xor(cross, oldR), umfsM)
	}

	shift := bitn - 2281
	if shift < 0 {
		shift = 0
	}
	res := new(big.Int).Xor(new(big.Int).Lsh(u.r, uint(shift)), u.c)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bitn)), big.NewInt(1))
	res.And(res, mask)

	hexLen := (bitn + 3) / 4
	hexStr := res.Text(16)
	for len(hexStr) < hexLen {
		hexStr = "0" + hexStr
	}
	return hexStr
}

func (u *UMFS) Digest() []byte {
	hx := u.HexDigest(256)
	b, _ := hex.DecodeString(hx)
	return b
}

func umfsHash(data []byte) string {
	return NewUMFS(data).HexDigest(256)
}

type UMFSHash struct {
	umfs *UMFS
}

func NewUMFSHash() *UMFSHash {
	return &UMFSHash{umfs: NewUMFS(nil)}
}

func (h *UMFSHash) Write(p []byte) (n int, err error) {
	h.umfs.pending.Write(p)
	return len(p), nil
}

func (h *UMFSHash) Sum(in []byte) []byte {
	savedR := new(big.Int).Set(h.umfs.r)
	savedC := new(big.Int).Set(h.umfs.c)
	savedLen := h.umfs.totalLen
	savedPool := append([]*big.Int{}, h.umfs.dataPool...)
	savedPending := make([]byte, h.umfs.pending.Len())
	copy(savedPending, h.umfs.pending.Bytes())

	result := h.umfs.Digest()

	h.umfs.r = savedR
	h.umfs.c = savedC
	h.umfs.totalLen = savedLen
	h.umfs.dataPool = savedPool
	h.umfs.pending.Reset()
	h.umfs.pending.Write(savedPending)

	return append(in, result...)
}

func (h *UMFSHash) Reset() {
	h.umfs = NewUMFS(nil)
}

func (h *UMFSHash) Size() int      { return 32 }
func (h *UMFSHash) BlockSize() int { return umfsBlockSize }

func generateUMFSToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return umfsHash(b)
	}
	return umfsHash(b)
}

var _ hash.Hash = (*UMFSHash)(nil)

// ===== 文件完整性校验辅助 =====

// sha512File 计算文件 SHA-512
func sha512File(path string) (string, error) {
	return hashFileHex(crypto.SHA512, path)
}

// umfsFile 流式计算文件 UMFS-256 十六进制摘要（bool-hybrid-array 生态）。
// 注意：UMFS 是整块吸收的海绵，这里把文件分块喂给 hash.Hash 接口的 Write，
// 在 Sum 时一次性 squeeze，与 Python 版对整文件 hexdigest 等价。
func umfsFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := NewUMFSHash()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
