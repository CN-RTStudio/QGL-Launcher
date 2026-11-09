package main

import (
	"bytes"
	"math/big"
)

func umfsMod(x *big.Int) *big.Int {
	return new(big.Int).And(x, umfsM)
}

func umfsPow(x, e *big.Int) *big.Int {
	return new(big.Int).Exp(x, e, umfsM)
}

// tenthOrderMapping 十阶模幂置换
func tenthOrderMapping(x *big.Int) *big.Int {
	p1 := umfsPow(x, umfs210)
	p2 := umfsPow(umfs210, x)
	p3 := umfsPow(x, x)
	x = umfsMod(new(big.Int).Sub(new(big.Int).Add(new(big.Int).Add(p1, p2), p3), big.NewInt(1)))

	x = new(big.Int).Xor(umfsPow(x, umfsE1), umfsC1)
	x = umfsMod(new(big.Int).Add(umfsPow(x, umfsE2), umfsC2))

	xShr := umfsMod(new(big.Int).Rsh(x, 18))
	xShl := umfsMod(new(big.Int).Lsh(x, 9))
	x = new(big.Int).Xor(new(big.Int).Xor(umfsPow(x, umfsE3), xShr), xShl)

	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE4), umfsC3))
	x = new(big.Int).Xor(umfsPow(x, umfsE5), umfsMod(new(big.Int).Lsh(x, 21)))
	x = new(big.Int).Xor(umfsPow(x, umfsE6), umfsC4)
	x = umfsMod(new(big.Int).Sub(umfsPow(x, umfsE7), umfsC6))

	xS12 := umfsMod(new(big.Int).Rsh(x, 12))
	xS15 := umfsMod(new(big.Int).Lsh(x, 15))
	x = new(big.Int).Xor(umfsPow(x, umfsE8), new(big.Int).And(xS12, xS15))

	x = umfsMod(new(big.Int).Mul(umfsPow(x, umfsE9), umfsC6))
	x = new(big.Int).Xor(umfsPow(x, umfsE10), umfsMod(new(big.Int).Lsh(x, 33)))

	return new(big.Int).Mod(x, umfsM)
}

type UMFS struct {
	r        *big.Int
	c        *big.Int
	totalLen int
	dataPool []*big.Int
	pending  bytes.Buffer
}
