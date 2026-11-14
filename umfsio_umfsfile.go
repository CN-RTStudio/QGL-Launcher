package main

import (
	"encoding/hex"
	"io"
	"math/big"
	"math/bits"
	"os"
)

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
