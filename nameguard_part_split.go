package main

import (
	"path/filepath"
	"strings"
)

func SafeAccountName(name string) (string, string) {
	clean := strings.TrimSpace(name)
	if why := auditComponent(clean, maxAccountNameLen); why != nameRejectNone {
		return "", why
	}
	return clean, nameRejectNone
}

// （"<customName> (<loaderName> <loaderVersion>)"），它同样会成为版本目录名。
func SafeVersionDisplayName(name string) (string, string) {
	clean := strings.TrimSpace(name)
	if why := auditComponent(clean, maxVersionDisplayLen); why != nameRejectNone {
		return "", why
	}
	return clean, nameRejectNone
}

// SafeLoaderComponent 校验加载器名 / 加载器版本这类“内部允许点号”的短标识，
// 例如 fabric / 0.16.10 / 53.0.12。规则与版本名一致，只是长度上限更小。
func SafeLoaderComponent(value string) (string, string) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return "", nameRejectEmpty
	}
	if why := auditComponent(clean, maxLoaderComponentLen); why != nameRejectNone {
		return "", why
	}
	// fabric / forge / 版本号这类加载器标识来自加载器元数据，是无空格的 token；
	// 内部空格只可能来自异常或伪造数据，拼进展示名 / 路径会引入歧义，单独拒绝。
	if strings.ContainsRune(clean, ' ') {
		return "", nameRejectInnerSpace
	}
	return clean, nameRejectNone
}

// SafeModFileName 校验模组落盘文件名。先强制只取最后一段（服务端文件名里
// 即便带目录也不允许建子目录），再过单段规则，最后要求扩展名在白名单。
// 返回干净文件名与拒绝原因码。
func SafeModFileName(name string) (string, string) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", nameRejectEmpty
	}
	if why := auditComponent(base, maxModFileComponentLen); why != nameRejectNone {
		return "", why
	}
	lower := strings.ToLower(base)
	okExt := false
	for ext := range allowedModFileExts {
		if strings.HasSuffix(lower, ext) {
			okExt = true
			break
		}
	}
	if !okExt {
		return "", nameRejectExtension
	}
	return base, nameRejectNone
}

// PickSafeModFileName 按候选顺序挑一个能通过 SafeModFileName 的文件名，
// 全部失败时回退到固定安全名。用于服务端给的主文件名不可信、需要多级兜底的场景。
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
