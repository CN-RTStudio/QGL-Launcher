package main

import (
	"strings"
)

// mrpackenv.go —— .mrpack 清单 files[].env 的客户端选取纯逻辑内核。
//
// Modrinth 整合包规范里，每个文件可带 env：{"client":"required|optional|unsupported",
// "server":"..."}。客户端启动器只能安装 client 侧不是 unsupported 的文件；旧实现
// 完全没有这个字段，等于把“服务器专用 mod”（client=unsupported）也下载安装到玩家
// 客户端里：既白白占用磁盘 / 下载量（与本轮磁盘预算直接相关），又可能因为服务端专用
// mod 在客户端加载而导致崩溃。
//
// 本文件只做纯函数：归一化 env 取值、判断单个文件客户端是否需要、按顺序确定性选取
// （含按规范化路径去重）。安装循环只迭代被选中的下标。

const (
	mrpackEnvKeyClient = "client"
	mrpackEnvKeyServer = "server"

	mrpackEnvRequired    = "required"
	mrpackEnvOptional    = "optional"
	mrpackEnvUnsupported = "unsupported"
)

// normalizeMrpackEnvSide 把 env 某一侧的原始取值归一化。
// 只接受规范的三个值（大小写 / 空白不敏感）；任何未知取值返回空串，由调用方按
// “未声明”对待（未知不等于 unsupported，不能据此拒绝正常文件）。
func normalizeMrpackEnvSide(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case mrpackEnvRequired:
		return mrpackEnvRequired
	case mrpackEnvOptional:
		return mrpackEnvOptional
	case mrpackEnvUnsupported:
		return mrpackEnvUnsupported
	default:
		return ""
	}
}
