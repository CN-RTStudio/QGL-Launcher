package main

// auditAssetObjects 遍历一份资产索引的 objects 表，把合法对象收集出来，
// 同时统计各类拒绝条数。对象条数超过上限直接返回 aoIndexTooMany。
// 输出顺序按 map 遍历不确定，调用方不应依赖顺序。
func auditAssetObjects(objects map[string]AssetObject) ([]SafeAssetObject, map[string]int, string) {
	if len(objects) > maxAssetIndexObjects {
		return nil, nil, aoIndexTooMany
	}
	safe := make([]SafeAssetObject, 0, len(objects))
	rejects := map[string]int{}
	for name, obj := range objects {
		cleanName, whyName := validateAssetObjectName(name)
		if whyName != aoOK {
			rejects[whyName]++
			continue
		}
		if !validateAssetObjectHash(obj.Hash) {
			rejects[aoHashBad]++
			continue
		}
		if !validateAssetObjectSize(obj.Size) {
			rejects[aoSizeBad]++
			continue
		}
		safe = append(safe, SafeAssetObject{Name: cleanName, Hash: obj.Hash, Size: obj.Size})
	}
	return safe, rejects, aoOK
}

// describeAssetReject 把资产对象拒绝原因码转成中文说明。
func describeAssetReject(why string) string {
	switch why {
	case aoRejectEmpty:
		return "资源名为空"
	case aoRejectLen:
		return "资源相对路径超过长度上限"
	case aoRejectAbs:
		return "资源名不允许是绝对路径"
	case aoRejectDrive:
		return "资源名不允许包含盘符"
	case aoRejectBack:
		return "资源名不允许包含反斜杠"
	case aoRejectCtrl:
		return "资源名包含控制字符"
	case aoRejectSeg:
		return "资源名包含非法路径段"
	case aoRejectTrail:
		return "资源名存在目录穿越"
	case aoHashBad:
		return "资源哈希不是 40 位小写十六进制"
	case aoSizeBad:
		return "资源声明大小非法"
	case aoIndexTooMany:
		return "资产索引声明的对象条数超过上限"
	default:
		return "资源对象未通过校验"
	}
}
