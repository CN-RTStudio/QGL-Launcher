package main

import (
)

func min3(a, b, c int) int {
	if a < b { if a < c { return a } else { return c } }
	if b < c { return b }
	return c
}

// isChinese 判断字符串是否包含中文
