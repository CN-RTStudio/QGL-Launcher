package main

import (
	"encoding/hex"
	"math/big"
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
