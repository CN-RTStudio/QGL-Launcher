package main

import ()

func constantTimeEqualLowerHex(actual, expected string) bool {
	if len(actual) != len(expected) {
		return false
	}
	var v byte
	for i := 0; i < len(actual); i++ {
		v |= actual[i] ^ expected[i]
	}
	return v == 0
}

// wrapClientRedirectGuard 复制客户端并替换成受控重定向策略。不就地修改调用方
// 传入的 client，避免把一次性下载的收紧策略带给其它请求。
