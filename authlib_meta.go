package main

// maxAuthlibMetaBytes 是 authlib 侧车元数据（.sha256meta）读取上限：正常仅数百字节，
// 取 1MiB 极宽值，只拦被改写成异常巨大文件导致的整体读入 OOM。
const maxAuthlibMetaBytes int64 = 1 << 20

// authlib-injector.jar 是通过 -javaagent 加载进游戏 JVM 的可执行字节码，
// 一旦被篡改 / 替换就是代码执行（RCE）。它的信任锚是官方 latest.json 给出的
// SHA-256（不是 Mojang 的 SHA-1），因此不能复用 cachemeta.go 那套以 SHA-1 为锚
// 的侧车，单独维护一个只认 SHA-256 的元数据文件。
//
// 侧车与 jar 同目录、同权限（0600），记录权威 SHA-256 与字节数：
// 每次启动若 jar 已存在，先用它做廉价尺寸预检 + 强哈希复核，通过才复用，
// 杜绝"文件在就直接 -javaagent 跑"的旧行为。

type authlibMeta struct {
	SHA256 string `json:"sha256"` // 官方 latest.json 给出的权威 SHA-256（小写）
	Size   int64  `json:"size"`   // 字节数，先做廉价预检
}

func authlibMetaPath(jarPath string) string {
	return jarPath + ".sha256meta"
}

// loadAuthlibMeta 读取侧车；不存在或内容损坏时 ok=false（调用方应视为不可信）。
func loadAuthlibMeta(jarPath string) (authlibMeta, bool) {
	var m authlibMeta
	// 侧车是本地小 JSON，走有界读取：缺失 / 损坏 / 被改成超大体积都判为不可信，
	// 绝不无界整体读入；超量由 readLocalJSONBounded 写安全审计。
	if err := readLocalJSONBounded(authlibMetaPath(jarPath), &m, maxAuthlibMetaBytes, "authlib侧车元数据"); err != nil {
		return m, false
	}
	if m.SHA256 == "" || m.Size <= 0 {
		return m, false
	}
	return m, true
}

// saveAuthlibMeta 在 jar 已通过官方 SHA-256 校验后原子写入侧车。
func saveAuthlibMeta(jarPath, expectedSHA256 string, size int64) error {
	m := authlibMeta{SHA256: expectedSHA256, Size: size}
	// 统一走有界原子私有写内核（0600 + fsync + rename + 拒符号链接 + 父目录收权），
	// 替换此前手写 tmp→rename（缺 fsync / 符号链接防护）。
	return writePrivateJSON(authlibMetaPath(jarPath), m)
}
