package main

import (
	"fmt"
)

// describeMrpackReject 把拒绝原因码转成中文说明。
func describeMrpackReject(why string) string {
	switch why {
	case mrpRejectEmptyPath:
		return "文件路径为空"
	case mrpRejectControl:
		return "文件路径包含非法控制字符"
	case mrpRejectBackslash:
		return "文件路径必须使用 '/' 分隔，不允许反斜杠"
	case mrpRejectAbsolute:
		return "文件路径不允许以 '/' 开头"
	case mrpRejectDrive:
		return "文件路径不允许带盘符 / UNC"
	case mrpRejectBadSegment:
		return "文件路径含空段、'.'、'..' 或非法目录名"
	case mrpRejectPathTooLong:
		return "文件路径超过长度上限"
	case mrpRejectPrivateDir:
		return "整合包不允许写入启动器私有目录 QGL/"
	case mrpRejectRootFile:
		return "整合包文件不允许直接写在实例目录根部（仅允许白名单子目录）"
	case mrpRejectRootSensitive:
		return "拒绝在实例目录根部写入启动配置 / 可执行 / 脚本文件"
	case mrpRejectBadExt:
		return "文件扩展名不被该目录允许"
	case mrpRejectFormat:
		return "formatVersion 必须为 1"
	case mrpRejectGame:
		return "game 必须为 minecraft"
	case mrpRejectNameControl:
		return "整合包名称包含非法控制字符"
	case mrpRejectNameTooLong:
		return "整合包名称过长"
	case mrpRejectTooManyFiles:
		return "清单声明的文件数量超过上限"
	case mrpRejectNoHash:
		return "文件缺少 sha1/sha512 完整性哈希"
	case mrpRejectBadHashAlg:
		return "哈希算法只允许 sha1/sha512"
	case mrpRejectBadHashValue:
		return "哈希值不是合法的十六进制或长度不符"
	case mrpRejectNoDownload:
		return "文件没有可用的下载地址"
	case mrpRejectTooManyURLs:
		return "单文件下载镜像数量超过上限"
	case mrpRejectURLScheme:
		return "下载地址必须使用 https://"
	case mrpRejectURLUserInfo:
		return "下载地址不允许携带用户信息(userinfo)"
	case mrpRejectURLHost:
		return "下载地址缺少有效主机名"
	case mrpRejectURLPrivate:
		return "下载地址指向内网 / 回环地址"
	case mrpRejectURLTooLong:
		return "下载地址超过长度上限"
	case mrpRejectURLDup:
		return "下载地址存在重复镜像"
	case mrpRejectBadFileSize:
		return "fileSize 为负数或超过单文件上限"
	case mrpRejectDepKey:
		return "dependencies 含不被识别的依赖键"
	default:
		return "整合包清单未通过安全校验"
	}
}

// mrpackReject 记录一次整合包清单被拦截的安全事件并返回错误。
func mrpackReject(why, detail string) error {
	recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
		"mrpackguard", describeMrpackReject(why)+"："+detail)
	return fmt.Errorf("%s", describeMrpackReject(why))
}
