package main

import (
	"fmt"
)

func loadOrCreateAuthSalt(saltPath string, create bool) ([]byte, bool, error) {
	// 盐文件也不允许是预置的符号链接，否则攻击者可以喂给程序一个已知盐。
	if bad, err := isSymlinkOrSpecial(saltPath); err != nil {
		return nil, false, err
	} else if bad {
		return nil, false, fmt.Errorf("盐文件是符号链接或非普通文件，已拒绝: %s", saltPath)
	}
	// 盐正常就是 16 字节随机串，取 1KiB 这种极宽上限只拦被塞成超大文件的异常读入；
	// 读取失败（含超量）沿用旧逻辑：create 时重新生成，否则回退旧硬编码盐。
	if data, err := readBoundedFile(saltPath, maxAuthSaltBytes); err == nil && len(data) >= 16 {
		return data, false, nil
	}
	if !create {
		return nil, false, nil
	}
	// 使用 mt_xor25（bool-hybrid-array 生态）生成 16 字节随机盐
	salt := mtXOR25Bytes(16)
	if err := secureWritePrivateFile(saltPath, salt); err != nil {
		return nil, false, err
	}
	return salt, true, nil
}

// aesGCMEncrypt 使用 AES-GCM 加密数据，返回 base64 编码的密文
