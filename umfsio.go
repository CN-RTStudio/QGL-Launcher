package main

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"math/bits"
	"os"
)

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
func (h *UMFSHash) Size() int { return 32 }

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

func NewUMFS(data []byte) *UMFS {
	u := &UMFS{
		r:        new(big.Int).Set(umfsIVR),
		c:        new(big.Int).Set(umfsIVC),
		totalLen: 0,
		dataPool: make([]*big.Int, 0),
	}
	if len(data) > 0 {
		u.pending.Write(data)
	}
	return u
}

// Absorb 与 bool-hybrid-array core.py UltraMersenneFractalSponge.absorb 对齐：
// 数据不是整段转成一个大整数，而是按 step = n // bitlen(n) 切块，逐块转大整数
// 入池并更新海绵状态。旧实现把整段当一个大整数吸收，切块粒度与上游不一致，
// 会让任何长度超过单块的数据得到与 Python 生态不同的摘要。
func (u *UMFS) Absorb(data []byte) *UMFS {
	n := len(data)
	if n == 0 {
		return u
	}
	u.totalLen += n
	step := n / bits.Len(uint(n))
	for i := 0; i < n; i += step {
		j := i + step
		if j > n {
			j = n
		}
		num := new(big.Int).SetBytes(data[i:j])
		u.dataPool = append(u.dataPool, num)
		u.r = tenthOrderMapping(new(big.Int).Xor(u.r, num))
		// term = (num^7 mod M * r) mod M，这里必须是模 M，不能用按位与近似。
		term := new(big.Int).Mod(new(big.Int).Mul(umfsPow(num, umfs7), u.r), umfsM)
		// Python 表达式 self.c = (self.c ^ self.r + term) % M 中，'+' 优先级
		// 高于 '^'，真实含义是 c ^ (r + term)，而非 (c ^ r) + term。
		u.c = new(big.Int).Mod(new(big.Int).Xor(u.c, new(big.Int).Add(u.r, term)), umfsM)
	}
	return u
}

func (u *UMFS) flushPending() {
	if u.pending.Len() > 0 {
		u.Absorb(u.pending.Bytes())
		u.pending.Reset()
	}
}

func (u *UMFS) foldRecursive(arr []*big.Int) *big.Int {
	if len(arr) <= 2 {
		res := big.NewInt(0)
		for _, v := range arr {
			res = new(big.Int).Mod(new(big.Int).Add(res, tenthOrderMapping(new(big.Int).Xor(v, res))), umfsM)
		}
		return res
	}
	mid := len(arr) >> 1
	left := u.foldRecursive(arr[:mid])
	right := u.foldRecursive(arr[mid:])
	l3 := umfsPow(left, umfs3)
	r3 := umfsPow(right, umfs3)
	// Python：cross = (left*right ^ l3 + r3) % M。'+' 优先级高于 '^'，
	// 真实含义是 (l*r) ^ (l3+r3)，旧实现误写成 ((l*r)^l3)+r3。
	cross := new(big.Int).Mod(
		new(big.Int).Xor(new(big.Int).Mul(left, right), new(big.Int).Add(l3, r3)),
		umfsM)
	return tenthOrderMapping(cross)
}
