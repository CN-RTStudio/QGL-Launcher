package main

const (
	// maxAssetIndexObjects 单份资产索引允许声明的对象条数上限。
	// 真实存量索引约数万条；取 200000 足够覆盖，同时挡住“百万对象”内存 / 调度耗尽。
	// 这是遍历调度的内存闸，不是磁盘容量闸，不限制单个资源文件大小（另有 maxAssetObjectBytes）。
	maxAssetIndexObjects = 200000
	// maxAssetObjectNameLen 单个资源相对路径（objects 的 key）长度上限。
	maxAssetObjectNameLen = 512
	// maxAssetObjectSizeDecl 索引里声明的 size 字段上限，必须与实际落盘上限一致量级。
	maxAssetObjectSizeDecl = maxAssetObjectBytes
)
const (
	aoOK           = ""
	aoRejectEmpty  = "asset-name-empty"
	aoRejectLen    = "asset-name-too-long"
	aoRejectAbs    = "asset-name-absolute"
	aoRejectDrive  = "asset-name-drive"
	aoRejectBack   = "asset-name-backslash"
	aoRejectCtrl   = "asset-name-control"
	aoRejectSeg    = "asset-name-bad-segment"
	aoRejectTrail  = "asset-name-traversal"
	aoHashBad      = "asset-hash-bad"
	aoSizeBad      = "asset-size-bad"
	aoIndexTooMany = "asset-index-too-many-objects"
)

func isAssetNameSegmentOK(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	for _, c := range seg {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
