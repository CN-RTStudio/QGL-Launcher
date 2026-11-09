package main

func PickSafeModFileName(candidates ...string) string {
	for _, c := range candidates {
		if clean, why := SafeModFileName(c); why == nameRejectNone {
			return clean
		}
	}
	return "mod.jar"
}

// describeNameReject 把拒绝原因码转成中文说明，供错误信息/安全事件使用。
func describeNameReject(why string) string {
	switch why {
	case nameRejectEmpty:
		return "名称为空"
	case nameRejectControl:
		return "名称包含非法控制字符"
	case nameRejectSeparator:
		return "名称不允许包含路径分隔符"
	case nameRejectForbidden:
		return "名称包含文件名非法字符 : * ? \" < > |"
	case nameRejectTraversal:
		return "名称不允许为 . 或 .."
	case nameRejectReserved:
		return "名称命中 Windows 保留设备名（CON/PRN/AUX/NUL/COM/LPT）"
	case nameRejectOuterSpace:
		return "名称不允许以空格开头或结尾"
	case nameRejectOuterDot:
		return "名称不允许以点开头或结尾"
	case nameRejectInnerSpace:
		return "加载器标识不允许包含内部空格"
	case nameRejectLength:
		return "名称超过单段长度上限"
	case nameRejectExtension:
		return "模组文件扩展名不在允许列表（.jar/.zip/.jar.disabled）"
	case nameRejectInvisible:
		return "名称包含零宽空格 / 软连字符 / BOM 等不可见字符"
	case nameRejectBidi:
		return "名称包含双向覆写控制字符（可反转显示顺序，用于仿冒）"
	case nameRejectNonchar:
		return "名称包含 Unicode 永久非字符"
	default:
		return "名称未通过安全校验"
	}
}
