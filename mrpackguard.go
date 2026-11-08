package main

// mrpackguard.go —— 不可信 .mrpack（Modrinth 整合包）清单结构与落盘路径安全内核。
//
// 威胁模型：
//   .mrpack 来自任意第三方下载源，modrinth.index.json 完全由打包者控制。下载完的
//   files[] 会被写进“版本实例目录”，overrides/ 也会解压到同一目录。这里有两类旧缺口：
//
//   1. 启动配置覆盖 -> 代码执行：实例目录里同时放着启动器信任的启动配置
//      versions/<id>/<id>.json（mainClass / libraries / 启动参数）与可能的同名 jar。
//      历史实现对 files[].path 只做“是否含 .. / NUL”的旧 safeJoin 判定，对 overrides
//      只防 Zip Slip / 符号链接 / 炸弹。恶意整合包可以把一个条目命名成实例目录根部的
//      <id>.json，把 mainClass 指向随包带入的恶意类。更关键的是：清单里的
//      sha1/sha512 由打包者自己填写，只保证“下载内容与清单一致”，不是信任锚——
//      打包者同时控制内容与哈希，校验通过毫无意义。下次用该版本启动即 RCE。
//
//   2. 清单字段畸形 -> 拖垮 / 混淆：files 数量无上限、downloads 镜像数量无上限且不去重、
//      fileSize 可以为负、哈希算法名与十六进制不校验、formatVersion/game 不检查、
//      dependencies 可塞任意键。单个畸形清单可以制造海量无效下载尝试，或把奇怪值
//      拼进后续 URL / 路径。
//
// 本内核“拒绝而非静默清洗”：任何字段越界都返回原因码，由安装流程整体中止并记安全事件。
// 路径策略复用 nameguard 的单段规则，避免重复实现保留设备名 / 控制字符 / 尾点空格判定。

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// 清单规模上限。正常整合包远小于此，只有刻意制造的畸形 / 轰炸清单才会触发。
// 阈值刻意从宽（与仓内“宁可炸磁盘也不误限正常数据”的取向一致），但必须是有限值。
const (
	// maxMrpackIndexFiles 单个清单允许声明的文件条目数上限。
	maxMrpackIndexFiles = 20000
	// maxMrpackMirrorsPerFile 单个文件允许给出的下载镜像数上限（Modrinth 正常只给 1 个）。
	maxMrpackMirrorsPerFile = 20
	// maxMrpackRelPathLen 落盘相对路径总长度上限（给前面的实例目录绝对路径留余量）。
	maxMrpackRelPathLen = 512
	// maxMrpackSegmentLen 路径单段长度上限，复用 nameguard 的保守取向。
	maxMrpackSegmentLen = maxModFileComponentLen
	// maxMrpackDownloadURLLen 单个下载 URL 长度上限，防超长 URL 拖慢解析与日志。
	maxMrpackDownloadURLLen = 2048
	// maxMrpackNameLen 整合包展示名长度上限（仅展示，不进路径）。
	maxMrpackNameLen = 200
	// maxMrpackDeclaredFileSize 清单声明的单文件体积上限；与整合包本体 8GiB 上限对齐。
	maxMrpackDeclaredFileSize = maxMrpackDownloadBytes
)

// files[] 允许写入的实例子目录白名单。Modrinth 整合包的数据文件只该落在这些目录，
// 绝不该出现在实例目录根部（根部是启动配置 / jar 所在地）。
var mrpackAllowedSubroots = map[string]bool{
	"mods":           true,
	"resourcepacks":  true,
	"shaderpacks":    true,
	"config":         true,
	"defaultconfigs": true,
	"kubejs":         true,
	"scripts":        true,
	"patch":          true,
}

// 启动器私有目录：绝不允许整合包写入（QGL/ 存放 config.json、umfs_cache.json 等）。
const mrpackPrivateSubroot = "QGL"

// 实例目录根部命中即拒绝的扩展名：启动配置、可执行 / 脚本文件。
var mrpackSensitiveRootExts = map[string]bool{
	".json": true, ".jar": true, ".exe": true, ".bat": true,
	".cmd": true, ".ps1": true, ".sh": true, ".com": true, ".scr": true,
}

// mods 目录允许的扩展名（复用 nameguard 的 mod 扩展名白名单）。
// resourcepacks / shaderpacks 只允许 .zip；其余子目录允许任意数据文件（.json 配置等）。
var mrpackPackArchiveExts = map[string]bool{".zip": true}

// mrpack 拒绝原因码（空串表示通过）。
const (
	mrpRejectNone         = ""
	mrpRejectEmptyPath    = "empty-path"
	mrpRejectControl      = "control-byte"
	mrpRejectBackslash    = "backslash"
	mrpRejectAbsolute     = "absolute-path"
	mrpRejectDrive        = "drive-prefix"
	mrpRejectBadSegment   = "bad-segment"
	mrpRejectPathTooLong  = "path-too-long"
	mrpRejectPrivateDir   = "private-subroot"
	mrpRejectRootFile     = "root-file"
	mrpRejectRootSensitive = "sensitive-root-file"
	mrpRejectBadExt       = "bad-extension"
	mrpRejectFormat       = "bad-format-version"
	mrpRejectGame         = "bad-game"
	mrpRejectNameControl  = "name-control"
	mrpRejectNameTooLong  = "name-too-long"
	mrpRejectTooManyFiles = "too-many-files"
	mrpRejectNoHash       = "missing-hash"
	mrpRejectBadHashAlg   = "bad-hash-algorithm"
	mrpRejectBadHashValue = "bad-hash-value"
	mrpRejectNoDownload   = "missing-download"
	mrpRejectTooManyURLs  = "too-many-downloads"
	mrpRejectURLScheme    = "url-not-https"
	mrpRejectURLUserInfo  = "url-userinfo"
	mrpRejectURLHost      = "url-bad-host"
	mrpRejectURLPrivate   = "url-private-host"
	mrpRejectURLTooLong   = "url-too-long"
	mrpRejectURLDup       = "duplicate-download"
	mrpRejectBadFileSize  = "bad-file-size"
	mrpRejectDepKey       = "bad-dependency-key"
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

// cleanMrpackPathSegments 把相对路径拆成已校验的干净段（'/' 连接）。
// 与 zipextract 的 secureZipRelPath 取向一致：不做平台 Clean，逐段手工判定，
// 保证 Windows / Linux 行为相同；这里更严格——空段 / '.' 也直接拒绝（不折叠）。
// 返回干净的 '/'-相对路径与拒绝原因码。
func cleanMrpackPathSegments(raw string) (string, string) {
	if raw == "" {
		return "", mrpRejectEmptyPath
	}
	if containsControlByte(raw) {
		return "", mrpRejectControl
	}
	if strings.ContainsRune(raw, '\\') {
		return "", mrpRejectBackslash
	}
	if strings.HasPrefix(raw, "/") {
		return "", mrpRejectAbsolute
	}
	// 盘符（C:x / C:/x）与 UNC（//host/share）在更前面已被前导 '/' 与盘符规则覆盖，
	// 这里再兜底一次任何位置的 "x:" 段前缀。
	if len(raw) >= 2 && raw[1] == ':' {
		return "", mrpRejectDrive
	}

	var segs []string
	for _, seg := range strings.Split(raw, "/") {
		switch seg {
		case "", ".", "..":
			return "", mrpRejectBadSegment
		}
		// 复用 nameguard 单段规则：保留设备名 / 控制字符 / 尾点尾空格 / 非法文件名字符。
		if why := auditComponent(seg, maxMrpackSegmentLen); why != nameRejectNone {
			return "", mrpRejectBadSegment
		}
		segs = append(segs, seg)
	}
	clean := strings.Join(segs, "/")
	if len(clean) > maxMrpackRelPathLen {
		return "", mrpRejectPathTooLong
	}
	return clean, mrpRejectNone
}

// mrpackPathPolicy 在“路径段已合法”的基础上施加实例目录写入策略。
// rel 必须是 cleanMrpackPathSegments 产出的 '/'-相对路径。
func mrpackPathPolicy(rel string) string {
	segs := strings.Split(rel, "/")
	top := segs[0]

	if top == mrpackPrivateSubroot {
		return mrpRejectPrivateDir
	}
	// 只有一级（直接位于实例目录根部）的文件一律拒绝：files[] 只允许落到白名单子目录，
	// 根部是 <id>.json / <id>.jar 等启动信任文件所在地。
	if len(segs) == 1 {
		return mrpRejectRootFile
	}
	if !mrpackAllowedSubroots[top] {
		return mrpRejectRootFile
	}

	base := segs[len(segs)-1]
	lower := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(base))

	switch top {
	case "mods":
		if !allowedModFileExts[lowerExt(lower)] {
			return mrpRejectBadExt
		}
	case "resourcepacks", "shaderpacks":
		if !mrpackPackArchiveExts[ext] {
			return mrpRejectBadExt
		}
	default:
		// config / kubejs / scripts 等目录允许数据文件，但根部敏感扩展名策略对
		// 任意层级的可执行 / 脚本仍生效，防止借子目录落 .jar / .exe。
		if mrpackSensitiveRootExts[ext] && ext != ".json" {
			return mrpRejectBadExt
		}
	}
	return mrpRejectNone
}

// 任意目录都不允许借整合包落地的可执行 / 脚本扩展名（.json 不在其中：config 等目录
// 里大量存在合法 .json 配置；根部 .json 由 mrpackSensitiveRootExts 单独拒绝）。
var mrpackRunnableExts = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".ps1": true,
	".sh": true, ".com": true, ".scr": true, ".vbs": true, ".jar": true,
}

// mrpackOverridePolicy 针对 overrides/ 解压条目的落盘策略，比 files[] 略宽：
// Modrinth 规范允许覆写目录根部放 options.txt / servers.dat 这类数据文件，
// 因此根部不做“只能白名单子目录”限制，但仍堵住代码执行与私有目录：
//   - QGL/ 任意层级一律拒绝（启动器私有配置）；
//   - 实例目录根部的启动配置 / 可执行（<id>.json、.jar、.exe 等）一律拒绝；
//   - mods/ 只允许 mod 扩展名，resourcepacks/shaderpacks 只允许 .zip；
//   - 其余子目录拒绝可执行 / 脚本（.exe/.bat/.../.jar），但允许 .json 等数据文件。
func mrpackOverridePolicy(rel string, isDir bool) string {
	if isDir {
		// 目录本身只要段合法即可；QGL 目录由“其下文件命中”即可整体阻断，
		// 这里对纯目录条目也直接拒绝，避免落地空的 QGL 目录。
		top := strings.SplitN(rel, "/", 2)[0]
		if top == mrpackPrivateSubroot {
			return mrpRejectPrivateDir
		}
		return mrpRejectNone
	}
	segs := strings.Split(rel, "/")
	top := segs[0]
	if top == mrpackPrivateSubroot {
		return mrpRejectPrivateDir
	}
	base := segs[len(segs)-1]
	lower := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(base))

	if len(segs) == 1 {
		if mrpackSensitiveRootExts[ext] {
			return mrpRejectRootSensitive
		}
		return mrpRejectNone
	}
	switch top {
	case "mods":
		if !allowedModFileExts[lowerExt(lower)] {
			return mrpRejectBadExt
		}
	case "resourcepacks", "shaderpacks":
		if !mrpackPackArchiveExts[ext] {
			return mrpRejectBadExt
		}
	default:
		if mrpackRunnableExts[ext] {
			return mrpRejectBadExt
		}
	}
	return mrpRejectNone
}

// validateMrpackPlannedEntries 对 overrides 的解压计划逐条施加 mrpackOverridePolicy。
// rel 必须已经过 zipextract 的 secureZipRelPath 段校验（zipPlannedEntry.rel 即此形态）。
func validateMrpackPlannedEntries(plan []zipPlannedEntry) error {
	for _, pe := range plan {
		if why := mrpackOverridePolicy(pe.rel, pe.dir); why != mrpRejectNone {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
				"mrpackguard", describeMrpackReject(why)+"：overrides/"+pe.rel)
			return fmt.Errorf("%s: overrides/%s", describeMrpackReject(why), pe.rel)
		}
	}
	return nil
}

// lowerExt 返回文件名（已小写）命中的扩展名；对 ".jar.disabled" 这类复合扩展优先返回它。
func lowerExt(lowerName string) string {
	for ext := range allowedModFileExts {
		if strings.HasSuffix(lowerName, ext) {
			return ext
		}
	}
	return filepath.Ext(lowerName)
}

// secureMrpackDestRel 校验并返回可安全拼接到实例目录的 '/'-相对路径。
func secureMrpackDestRel(raw string) (string, string) {
	clean, why := cleanMrpackPathSegments(raw)
	if why != mrpRejectNone {
		return "", why
	}
	if why := mrpackPathPolicy(clean); why != mrpRejectNone {
		return "", why
	}
	return clean, mrpRejectNone
}

// secureMrpackDest 把相对路径安全拼接到实例根目录，并做落盘前的“必须在根内”第二道复核。
func secureMrpackDest(baseDir, raw string) (string, error) {
	rel, why := secureMrpackDestRel(raw)
	if why != mrpRejectNone {
		return "", fmt.Errorf("%s: %s", describeMrpackReject(why), raw)
	}
	dest := filepath.Join(baseDir, filepath.FromSlash(rel))
	if !PathWithinRoot(dest, baseDir) {
		return "", fmt.Errorf("整合包文件解析后越出实例目录: %s", raw)
	}
	return dest, nil
}

// validateMrpackHash 校验单个文件的哈希表：键只能是 sha1/sha512，值必须是对应长度的
// 合法十六进制，且至少提供一个。返回错误原因码。
func validateMrpackHash(hashes map[string]string) string {
	if len(hashes) == 0 {
		return mrpRejectNoHash
	}
	for alg, val := range hashes {
		var wantLen int
		switch alg {
		case "sha1":
			wantLen = 40
		case "sha512":
			wantLen = 128
		default:
			return mrpRejectBadHashAlg
		}
		v := strings.TrimSpace(val)
		if len(v) != wantLen {
			return mrpRejectBadHashValue
		}
		if _, err := hex.DecodeString(v); err != nil {
			return mrpRejectBadHashValue
		}
	}
	if _, ok := hashes["sha1"]; !ok {
		if _, ok512 := hashes["sha512"]; !ok512 {
			return mrpRejectNoHash
		}
	}
	return mrpRejectNone
}

// normalizeMrpackDownloads 校验一个文件的下载镜像列表：
// 非空、数量上限、必须 https、无 userinfo、主机有效且不指向内网、规范化后去重。
// 返回清洗后的镜像列表与拒绝原因码。
func normalizeMrpackDownloads(in []string) ([]string, string) {
	if len(in) == 0 {
		return nil, mrpRejectNoDownload
	}
	if len(in) > maxMrpackMirrorsPerFile {
		return nil, mrpRejectTooManyURLs
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		u0 := strings.TrimSpace(raw)
		if u0 == "" {
			return nil, mrpRejectNoDownload
		}
		if len(u0) > maxMrpackDownloadURLLen {
			return nil, mrpRejectURLTooLong
		}
		if !isHTTPSURL(u0) {
			return nil, mrpRejectURLScheme
		}
		u, err := url.Parse(u0)
		if err != nil {
			return nil, mrpRejectURLScheme
		}
		if u.User != nil {
			return nil, mrpRejectURLUserInfo
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			return nil, mrpRejectURLHost
		}
		// 字符串态先拦一层内网 / 回环（DNS rebinding 由 safeHTTPClient 的拨号闸再兜）。
		if isPrivateDest(u0) {
			return nil, mrpRejectURLPrivate
		}
		norm := strings.ToLower(u.String())
		if seen[norm] {
			return nil, mrpRejectURLDup
		}
		seen[norm] = true
		out = append(out, u0)
	}
	return out, mrpRejectNone
}

// mrpackAllowedDepKeys 是 dependencies 允许出现的键（Modrinth 规范）。
var mrpackAllowedDepKeys = map[string]bool{
	"minecraft":     true,
	"forge":         true,
	"neoforge":      true,
	"fabric-loader": true,
	"quilt-loader":  true,
}

// validateMrpackDependencies 校验依赖键集合与各版本标识（复用 nameguard）。
// 通过后把清洗过的值写回 map，供安装流程直接使用。
func validateMrpackDependencies(deps map[string]string) string {
	for k, v := range deps {
		if !mrpackAllowedDepKeys[k] {
			return mrpRejectDepKey
		}
		val := strings.TrimSpace(v)
		if val == "" {
			// 空依赖值没有意义，按坏段处理（minecraft 必填在安装流程另行保证）。
			return mrpRejectBadSegment
		}
		if k == "minecraft" {
			clean, why := SafeVersionComponent(val)
			if why != nameRejectNone {
				return mrpRejectBadSegment
			}
			deps[k] = clean
			continue
		}
		clean, why := SafeLoaderComponent(val)
		if why != nameRejectNone {
			return mrpRejectBadSegment
		}
		deps[k] = clean
	}
	return mrpRejectNone
}

// validateMrpackManifest 对已解析的整合包清单做整体结构校验（就地规范化）。
// 任何越界都返回带中文原因的错误；调用方应中止安装。
func validateMrpackManifest(m *ModrinthModpackManifest) error {
	if m == nil {
		return mrpackReject(mrpRejectFormat, "清单为空")
	}
	if m.FormatVersion != 1 {
		return mrpackReject(mrpRejectFormat, fmt.Sprintf("formatVersion=%d", m.FormatVersion))
	}
	if strings.ToLower(strings.TrimSpace(m.Game)) != "minecraft" {
		return mrpackReject(mrpRejectGame, "game="+m.Game)
	}
	if m.Name != "" {
		if containsControlByte(m.Name) {
			return mrpackReject(mrpRejectNameControl, "")
		}
		if len(m.Name) > maxMrpackNameLen {
			return mrpackReject(mrpRejectNameTooLong, "")
		}
	}
	if why := validateMrpackDependencies(m.Dependencies); why != mrpRejectNone {
		return mrpackReject(why, "dependencies")
	}
	if len(m.Files) > maxMrpackIndexFiles {
		return mrpackReject(mrpRejectTooManyFiles, fmt.Sprintf("files=%d", len(m.Files)))
	}

	for i := range m.Files {
		f := &m.Files[i]
		rel, why := secureMrpackDestRel(f.Path)
		if why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d].path=%q", i, f.Path))
		}
		f.Path = rel

		if f.FileSize < 0 || f.FileSize > maxMrpackDeclaredFileSize {
			return mrpackReject(mrpRejectBadFileSize, fmt.Sprintf("files[%d].fileSize=%d", i, f.FileSize))
		}
		if why := validateMrpackHash(f.Hashes); why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d](%s)", i, rel))
		}
		downloads, why := normalizeMrpackDownloads(f.Downloads)
		if why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d](%s)", i, rel))
		}
		f.Downloads = downloads

		// env 只允许 client/server 两个键，取值仅限 required/optional/unsupported；
		// 未知键 / 未知取值就地清除（而非拒绝），避免第三方塞自定义键影响客户端选取。
		if f.Env != nil {
			cleaned := make(map[string]string, 2)
			for _, key := range []string{mrpackEnvKeyClient, mrpackEnvKeyServer} {
				if raw, present := f.Env[key]; present {
					if norm := normalizeMrpackEnvSide(raw); norm != "" {
						cleaned[key] = norm
					}
				}
			}
			if len(cleaned) == 0 {
				f.Env = nil
			} else {
				f.Env = cleaned
			}
		}
	}
	return nil
}
