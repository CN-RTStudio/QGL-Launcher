package main

var describeMrpackRejectTexts = map[string]string{
	mrpRejectEmptyPath:     "文件路径为空",
	mrpRejectControl:       "文件路径包含非法控制字符",
	mrpRejectBackslash:     "文件路径必须使用 '/' 分隔，不允许反斜杠",
	mrpRejectAbsolute:      "文件路径不允许以 '/' 开头",
	mrpRejectDrive:         "文件路径不允许带盘符 / UNC",
	mrpRejectBadSegment:    "文件路径含空段、'.'、'..' 或非法目录名",
	mrpRejectPathTooLong:   "文件路径超过长度上限",
	mrpRejectPrivateDir:    "整合包不允许写入启动器私有目录 QGL/",
	mrpRejectRootFile:      "整合包文件不允许直接写在实例目录根部（仅允许白名单子目录）",
	mrpRejectRootSensitive: "拒绝在实例目录根部写入启动配置 / 可执行 / 脚本文件",
	mrpRejectBadExt:        "文件扩展名不被该目录允许",
	mrpRejectFormat:        "formatVersion 必须为 1",
	mrpRejectGame:          "game 必须为 minecraft",
	mrpRejectNameControl:   "整合包名称包含非法控制字符",
	mrpRejectNameTooLong:   "整合包名称过长",
	mrpRejectTooManyFiles:  "清单声明的文件数量超过上限",
	mrpRejectNoHash:        "文件缺少 sha1/sha512 完整性哈希",
	mrpRejectBadHashAlg:    "哈希算法只允许 sha1/sha512",
	mrpRejectBadHashValue:  "哈希值不是合法的十六进制或长度不符",
	mrpRejectNoDownload:    "文件没有可用的下载地址",
	mrpRejectTooManyURLs:   "单文件下载镜像数量超过上限",
	mrpRejectURLScheme:     "下载地址必须使用 https://",
	mrpRejectURLUserInfo:   "下载地址不允许携带用户信息(userinfo)",
	mrpRejectURLHost:       "下载地址缺少有效主机名",
	mrpRejectURLPrivate:    "下载地址指向内网 / 回环地址",
	mrpRejectURLTooLong:    "下载地址超过长度上限",
	mrpRejectURLDup:        "下载地址存在重复镜像",
	mrpRejectBadFileSize:   "fileSize 为负数或超过单文件上限",
	mrpRejectDepKey:        "dependencies 含不被识别的依赖键",
}

var describeDownloadURLRejectTexts = map[string]string{
	dqURLRejectNone:      "通过",
	dqURLRejectScheme:    "URL 协议不是 http/https",
	dqURLRejectUserinfo:  "URL 含 user:pass@ 形式的内嵌凭据",
	dqURLRejectControl:   "URL 含控制字符、空白或 DEL",
	dqURLRejectBackslash: "URL 含反斜杠",
	dqURLRejectHost:      "URL 主机名为空或含前导/尾随点",
	dqURLRejectIPLiteral: "URL 直接使用 IP 字面量（含十进制/十六进制/短格式/IPv6）",
	dqURLRejectPort:      "URL 端口与协议默认端口不一致",
	dqURLRejectMalformed: "URL 结构不合法或缺少主机",
	dqURLRejectEncoding:  "URL 主机含百分号编码或非 ASCII 字符",
	dqURLRejectLong:      "URL 长度超过 4096 字节上限",
}

var describeAssetRejectTexts = map[string]string{
	aoRejectEmpty:  "资源名为空",
	aoRejectLen:    "资源相对路径超过长度上限",
	aoRejectAbs:    "资源名不允许是绝对路径",
	aoRejectDrive:  "资源名不允许包含盘符",
	aoRejectBack:   "资源名不允许包含反斜杠",
	aoRejectCtrl:   "资源名包含控制字符",
	aoRejectSeg:    "资源名包含非法路径段",
	aoRejectTrail:  "资源名存在目录穿越",
	aoHashBad:      "资源哈希不是 40 位小写十六进制",
	aoSizeBad:      "资源声明大小非法",
	aoIndexTooMany: "资产索引声明的对象条数超过上限",
}

var describeDownloadNameRejectTexts = map[string]string{
	dqNameRejectNone:      "通过",
	dqNameRejectEmpty:     "下载任务名称为空",
	dqNameRejectLong:      "下载任务名称超过 120 字节上限",
	dqNameRejectControl:   "下载任务名称含控制字符或 DEL",
	dqNameRejectSeparator: "下载任务名称含路径分隔符或 Windows 保留标点",
	dqNameRejectTraversal: "下载任务名称含 .. 路径穿越段",
	dqNameRejectReserved:  "下载任务名称命中 Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9）",
	dqNameRejectTrailing:  "下载任务名称以点或空格结尾",
}

var describePortProbeReasonTexts = map[string]string{
	portProbeFree:         "端口可用",
	portProbeInUse:        "端口已被其它程序占用，请更换端口或关闭占用程序",
	portProbePermission:   "系统拒绝绑定该端口（权限不足或被策略保留）",
	portProbeUnreachable:  "当前网络环境无法绑定该端口",
	portProbeInvalid:      "端口号无效",
	portProbeNotSupported: "当前系统不支持该端口绑定方式",
}

var describeConnRejectTexts = map[string]string{
	connRejectShape:   "连接码格式错误",
	connRejectPrefix:  "连接码首段前缀无法解析或越界",
	connRejectSegment: "连接码 IP 段解析失败",
	connRejectPort:    "解析出的端口号无效",
	connRejectAddress: "连接码还原的地址不合法",
}

var describeYggRejectTexts = map[string]string{
	ypNameEmpty: "外置服务器返回的角色名为空",
	ypNameLen:   "外置服务器返回的角色名长度不合法",
	ypNameChar:  "外置服务器返回的角色名包含非法字符",
	ypUUIDBad:   "外置服务器返回的角色 UUID 不是合法十六进制",
	ypTokenBad:  "外置服务器返回的访问令牌不合法",
}

func rejectReasonText(code, fallback string, table map[string]string) string {
	if t, ok := table[code]; ok {
		return t
	}
	return fallback
}
