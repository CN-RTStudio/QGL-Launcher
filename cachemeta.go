package main

// maxCachedFileMetaBytes 是下载侧车元数据（.qglmeta）读取上限：正常仅数百字节，
// 取 1MiB 这种极宽值，只拦截被改写成异常巨大文件导致的整体读入 OOM。
const maxCachedFileMetaBytes int64 = 1 << 20

// 本文件为本地下载缓存引入侧车完整性元数据（<file>.qglmeta）。
//
// 信任模型：
//   - SHA1 来自 Mojang / 官方版本清单，是文件首次下载时唯一的外部信任锚，
//     下载落盘后必须先用官方 SHA1 校验通过（downloadVerifiedFile 里保留这一步）。
//   - UMFS（bool-hybrid-array 生态）与 SHA512 是“文件已被确认可信”之后，
//     在本地额外计算并缓存下来的摘要，仅用于之后的缓存命中与比特腐烂检测，
//     不作为对抗主动攻击者的信任来源（本地可写者本就能改写游戏目录）。
//
// 缓存命中的摘要使用顺序按要求固定为：UMFS -> SHA512 -> SHA1。
// 注意“降级”只在对应字段“缺失”时发生；某字段存在但比对失败，意味着文件
// 已被改动或损坏，必须判定缓存失效并重新下载，而不是悄悄换更弱的算法放行。

// cachedFileMeta 是与下载产物同目录的侧车元数据。
type cachedFileMeta struct {
	SHA1   string `json:"sha1"`             // 官方清单给出的权威 SHA1（小写）
	SHA512 string `json:"sha512,omitempty"` // 本地计算的 SHA-512
	UMFS   string `json:"umfs,omitempty"`   // 本地计算的 UMFS-256（生态优先）
	Size   int64  `json:"size"`             // 字节数，先做廉价的尺寸预检
}

func metaPathFor(destPath string) string {
	return destPath + ".qglmeta"
}
