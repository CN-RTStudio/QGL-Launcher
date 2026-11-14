package main

import (
	"crypto"
	"crypto/rand"
	"hash"
)

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
