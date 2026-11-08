package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// 目录包含判定统一使用 sanitize.PathWithin：它除了词法边界检查，还做真实符号链接
// 解析（isPathInDir 旧实现只看 filepath.Rel，root 内被预置指向外部的链接时会漏判）。

// isValidModID 验证 Mod ID 格式，防止 URL 注入
func isValidModID(id string) bool {
	if len(id) > 100 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ===== Modrinth API 相关结构体 =====

type ModSearchResult struct {
	ProjectID    string   `json:"project_id"`
	Slug         string   `json:"slug"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	IconURL      string   `json:"icon_url"`
	Downloads    int      `json:"downloads"`
	ClientSide   string   `json:"client_side"`
	ServerSide   string   `json:"server_side"`
	Categories   []string `json:"categories"`
	GameVersions []string `json:"game_versions"`
	Loaders      []string `json:"loaders"`
}

type ModSearchResponse struct {
	Hits      []ModSearchResult `json:"hits"`
	TotalHits int               `json:"total_hits"`
	Offset    int               `json:"offset"`
	Limit     int               `json:"limit"`
}

type ModVersion struct {
	ID            string          `json:"id"`
	ProjectID     string          `json:"project_id"`
	Name          string          `json:"name"`
	VersionNumber string          `json:"version_number"`
	GameVersions  []string        `json:"game_versions"`
	Loaders       []string        `json:"loaders"`
	Files         []ModFile       `json:"files"`
	Dependencies  []ModDependency `json:"dependencies"`
	Changelog     string          `json:"changelog"`
}

type ModFile struct {
	Filename string            `json:"filename"`
	URL      string            `json:"url"`
	Size     int64             `json:"size"`
	Primary  bool              `json:"primary"`
	SHA1     string            `json:"sha1"`
	Hashes   map[string]string `json:"hashes"`
}

type ModDependency struct {
	ProjectID      string `json:"project_id"`
	VersionID      string `json:"version_id"`
	DependencyType string `json:"dependency_type"`
}

type ModDetail struct {
	ID           string   `json:"id"`
	Slug         string   `json:"slug"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Body         string   `json:"body"`
	IconURL      string   `json:"icon_url"`
	Downloads    int      `json:"downloads"`
	ClientSide   string   `json:"client_side"`
	ServerSide   string   `json:"server_side"`
	Categories   []string `json:"categories"`
	GameVersions []string `json:"game_versions"`
	Loaders      []string `json:"loaders"`
	ProjectType  string   `json:"project_type"`
}

type ModDependencyInfo struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	DependencyType string `json:"dependencyType"`
}

type ModCategory struct {
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	ProjectType string `json:"project_type"`
}

type ModFileInfo struct {
	FileName  string `json:"fileName"`
	FilePath  string `json:"filePath"`
	IsEnabled bool   `json:"isEnabled"`
	FileSize  int64  `json:"fileSize"`
}

const modrinthBaseURL = "https://api.modrinth.com/v2"

// 下载期望值（哈希/大小）的并发安全存储、完整性校验、下载主机白名单与
// 符号链接安全落盘都已收口到 modverify.go（var modExpect 等）。

// SearchMods 搜索 Mod
func (a *App) SearchMods(query string, gameVersion string, loader string, category string, page int, pageSize int) (*ModSearchResponse, error) {
	// 分页/查询入参全部来自前端，必须收敛，防止被传入超大 limit 打出超长 Modrinth
	// URL 或巨大的 offset。Modrinth 单页上限是 100，这里对齐并兜底；查询词做长度上限。
	const (
		defaultModPageSize = 20
		maxModPageSize     = 100
		maxModQueryLen     = 200
	)
	if pageSize <= 0 {
		pageSize = defaultModPageSize
	}
	if pageSize > maxModPageSize {
		pageSize = maxModPageSize
	}
	if page < 0 {
		page = 0
	}
	if len(query) > maxModQueryLen {
		query = query[:maxModQueryLen]
	}
	query = strings.TrimSpace(query)

	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", pageSize))
	params.Set("offset", fmt.Sprintf("%d", page*pageSize))
	params.Set("index", "relevance")

	var facets []string
	facets = append(facets, `["project_type:mod"]`)

	// 安全校验：过滤非法字符
	if gameVersion != "" && isValidMCVersion(gameVersion) {
		facets = append(facets, fmt.Sprintf(`["versions:%s"]`, gameVersion))
	}
	if loader != "" && isValidModID(loader) {
		facets = append(facets, fmt.Sprintf(`["categories:%s"]`, loader))
	}
	if category != "" && isValidModID(category) {
		facets = append(facets, fmt.Sprintf(`["categories:%s"]`, category))
	}

	if len(facets) > 0 {
		facetsJSON := fmt.Sprintf("[%s]", strings.Join(facets, ","))
		params.Set("facets", facetsJSON)
	}

	apiURL := fmt.Sprintf("%s/search?%s", modrinthBaseURL, params.Encode())

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("搜索 Mod 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp, "搜索 Mod 失败")
	}

	var result ModSearchResponse
	if err := readAPIJSON(resp, &result); err != nil {
		return nil, fmt.Errorf("解析搜索结果失败: %v", err)
	}

	if result.Hits == nil {
		result.Hits = []ModSearchResult{}
	}
	for i := range result.Hits {
		if result.Hits[i].Categories == nil {
			result.Hits[i].Categories = []string{}
		}
		if result.Hits[i].GameVersions == nil {
			result.Hits[i].GameVersions = []string{}
		}
		if result.Hits[i].Loaders == nil {
			result.Hits[i].Loaders = []string{}
		}
	}

	return &result, nil
}

// GetModDetail 获取 Mod 详情
func (a *App) GetModDetail(projectID string) (*ModDetail, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的 Mod ID 格式")
	}

	apiURL := fmt.Sprintf("%s/project/%s", modrinthBaseURL, projectID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 详情失败: HTTP %d", resp.StatusCode)
	}

	var detail ModDetail
	if err := readAPIJSON(resp, &detail); err != nil {
		return nil, fmt.Errorf("解析 Mod 详情失败: %v", err)
	}

	return &detail, nil
}

// GetModVersions 获取 Mod 版本列表
func (a *App) GetModVersions(projectID string, gameVersion string, loader string) ([]ModVersion, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的 Mod ID 格式")
	}

	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)

	params := url.Values{}
	if gameVersion != "" && isValidMCVersion(gameVersion) {
		gvJSON, _ := json.Marshal([]string{gameVersion})
		params.Set("game_versions", string(gvJSON))
	}
	if loader != "" && isValidModID(loader) {
		loaderJSON, _ := json.Marshal([]string{loader})
		params.Set("loaders", string(loaderJSON))
	}

	if len(params) > 0 {
		apiURL += "?" + params.Encode()
	}

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 版本失败: HTTP %d", resp.StatusCode)
	}

	var versions []ModVersion
	if err := readAPIJSON(resp, &versions); err != nil {
		return nil, fmt.Errorf("解析 Mod 版本失败: %v", err)
	}

	if versions == nil {
		versions = []ModVersion{}
	}
	for i := range versions {
		if versions[i].GameVersions == nil {
			versions[i].GameVersions = []string{}
		}
		if versions[i].Loaders == nil {
			versions[i].Loaders = []string{}
		}
		if versions[i].Files == nil {
			versions[i].Files = []ModFile{}
		}
		if versions[i].Dependencies == nil {
			versions[i].Dependencies = []ModDependency{}
		}
	}

	return versions, nil
}

// GetModDependencies 获取 Mod 依赖信息
func (a *App) GetModDependencies(versionID string) ([]ModDependencyInfo, error) {
	if !isValidModID(versionID) {
		return nil, fmt.Errorf("无效的版本 ID 格式")
	}

	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := readAPIJSON(resp, &version); err != nil {
		return nil, fmt.Errorf("解析版本详情失败: %v", err)
	}

	var deps []ModDependencyInfo
	if version.Dependencies == nil {
		return deps, nil
	}
	for _, dep := range version.Dependencies {
		if dep.ProjectID == "" {
			continue
		}

		depInfo := ModDependencyInfo{
			ProjectID:      dep.ProjectID,
			DependencyType: dep.DependencyType,
		}

		detail, err := a.GetModDetail(dep.ProjectID)
		if err == nil && detail != nil {
			depInfo.ProjectName = detail.Title
			depInfo.IconURL = detail.IconURL
		} else {
			depInfo.ProjectName = dep.ProjectID
		}

		deps = append(deps, depInfo)
	}

	return deps, nil
}

// AddModToDownloadList 添加 Mod 到下载列表
func (a *App) AddModToDownloadList(versionID string, savePath string) error {
	if !isValidModID(versionID) {
		return fmt.Errorf("无效的版本 ID 格式")
	}

	// 安全校验: savePath 若由前端指定，只能是受管 mods 目录（全局 mods 或版本隔离
	// mods）本身。旧实现只判定 PathWithin(mcDir)，渲染层可把下载的 jar 投放到
	// libraries / versions / mcDir 根等任意子目录（越权落盘）。
	if savePath != "" {
		mcDir := a.GetMinecraftDir()
		dirAbs, ok := resolveManagedModsDir(mcDir, savePath)
		if !ok {
			recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
				"AddModToDownloadList", "拒绝把 Mod 下载到受管 Mods 目录之外: "+savePath)
			return fmt.Errorf("保存路径必须是 Mods 目录")
		}
		savePath = dirAbs
	}

	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := readAPIJSON(resp, &version); err != nil {
		return fmt.Errorf("解析版本详情失败: %v", err)
	}

	var primaryFile *ModFile
	for i := range version.Files {
		if version.Files[i].Primary {
			primaryFile = &version.Files[i]
			break
		}
	}
	if primaryFile == nil && len(version.Files) > 0 {
		primaryFile = &version.Files[0]
	}
	if primaryFile == nil {
		return fmt.Errorf("未找到 Mod 文件")
	}

	// 安全校验：下载 URL 必须是 HTTPS 且主机在 Mod 下载白名单内
	// （官方 Modrinth/CurseForge CDN 与 mcimirror 镜像），防止被篡改的
	// 版本元数据把下载指向任意主机。
	if err := validateModDownloadURL(primaryFile.URL); err != nil {
		return err
	}

	// 登记 Modrinth 给的哈希和期望大小，下载完会校验（并发安全，详见 modverify.go）
	modExpect.record(primaryFile.URL, *primaryFile)

	if savePath == "" {
		mcDir := a.GetMinecraftDir()
		savePath = filepath.Join(mcDir, "mods")
	}

	if err := ensurePrivateDir(savePath); err != nil {
		return fmt.Errorf("创建保存目录失败: %w", err)
	}

	// 文件名来自 Modrinth 服务器元数据，filepath.Base 只能剥目录，挡不住控制字符、
	// Windows 保留设备名、尾点与可执行扩展名；统一走 nameguard，逐级回退到合法默认名。
	customName := PickSafeModFileName(primaryFile.Filename, version.Name)

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: customName,
		Type:       "mod",
		ItemType:   "mod",
		SavePath:   savePath,
		Status:     "pending",
		Progress:   0,
		// r35：把 Modrinth 声明大小带进队列，供聚合字节预算裁决；远端未给时为 0（未知）。
		SizeBytes: primaryFile.Size,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}

	a.downloadList = append(a.downloadList, pending)

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// ResolveModDependencies 解析 mod 的前置依赖
func (a *App) ResolveModDependencies(versionIDs []string, gameVersion string, loader string) ([]ModDependencyResult, error) {
	var results []ModDependencyResult
	visited := make(map[string]bool)

	for _, vid := range versionIDs {
		if !isValidModID(vid) {
			continue
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := safeHTTPClient().Get(apiURL)
		if err != nil {
			continue
		}
		var version ModVersion
		if err := readAPIJSON(resp, &version); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if version.ProjectID != "" {
			visited[version.ProjectID] = true
		}
	}

	var resolveDeps func(vid string, depth int) error
	resolveDeps = func(vid string, depth int) error {
		if depth > 5 {
			return nil
		}

		if !isValidModID(vid) {
			return nil
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := safeHTTPClient().Get(apiURL)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		var version ModVersion
		if err := readAPIJSON(resp, &version); err != nil {
			return nil
		}

		for _, dep := range version.Dependencies {
			if dep.DependencyType == "optional" || dep.DependencyType == "embedded" {
				continue
			}
			if dep.DependencyType != "required" {
				continue
			}
			if dep.ProjectID == "" {
				continue
			}
			if visited[dep.ProjectID] {
				continue
			}
			visited[dep.ProjectID] = true

			detail, err := a.GetModDetail(dep.ProjectID)
			if err != nil {
				continue
			}

			depVersionID := dep.VersionID
			if depVersionID == "" {
				versions, err := a.GetModVersions(dep.ProjectID, gameVersion, loader)
				if err != nil || len(versions) == 0 {
					continue
				}
				depVersionID = versions[0].ID
			}

			results = append(results, ModDependencyResult{
				ProjectID:      dep.ProjectID,
				ProjectName:    detail.Title,
				IconURL:        detail.IconURL,
				VersionID:      depVersionID,
				DependencyType: dep.DependencyType,
			})

			_ = resolveDeps(depVersionID, depth+1)
		}
		return nil
	}

	for _, vid := range versionIDs {
		_ = resolveDeps(vid, 0)
	}

	return results, nil
}

type ModDependencyResult struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	VersionID      string `json:"versionId"`
	DependencyType string `json:"dependencyType"`
}

// SelectModSaveDir 弹出选择 Mod 保存目录对话框
func (a *App) SelectModSaveDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 保存位置",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetDefaultModDir 获取默认 Mod 目录
func (a *App) GetDefaultModDir(versionID string) string {
	mcDir := a.GetMinecraftDir()
	if versionID != "" && !strings.Contains(versionID, "..") && !strings.Contains(versionID, "/") && !strings.Contains(versionID, "\\") {
		return filepath.Join(mcDir, "versions", versionID, "mods")
	}
	return filepath.Join(mcDir, "mods")
}

// GetModList 获取指定版本的 Mod 列表
func (a *App) GetModList(versionID string) ([]ModFileInfo, error) {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") || strings.Contains(versionID, "\\") {
			return nil, fmt.Errorf("版本ID包含非法字符")
		}
	}
	mcDir := a.GetMinecraftDir()
	var modsDir string

	if a.isVersionIsolated() && versionID != "" {
		modsDir = filepath.Join(mcDir, "versions", versionID, "mods")
	} else {
		modsDir = filepath.Join(mcDir, "mods")
	}

	mods := []ModFileInfo{}

	entries, err := os.ReadDir(modsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return mods, nil
		}
		return nil, fmt.Errorf("读取 Mod 目录失败: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		lowerName := strings.ToLower(name)

		isEnabled := true
		if strings.HasSuffix(lowerName, ".jar.disabled") {
			isEnabled = false
		} else if !strings.HasSuffix(lowerName, ".jar") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		mods = append(mods, ModFileInfo{
			FileName:  name,
			FilePath:  filepath.Join(modsDir, name),
			IsEnabled: isEnabled,
			FileSize:  info.Size(),
		})
	}

	return mods, nil
}

// ToggleMod 切换 Mod 启用/禁用状态
func (a *App) ToggleMod(modFilePath string, enable bool) error {
	mcDir := a.GetMinecraftDir()
	// 只允许操作“受管 mods 目录”（全局 mods 或版本隔离 mods）顶层的 .jar/.jar.disabled。
	// 旧实现只判定 PathWithin(mcDir)，等于放权整个 .minecraft，渲染层可借改名禁用
	// libraries/versions 里的任意 jar（破坏依赖）；这里收口到受管集合。
	curAbs, ok := resolveManagedModPath(mcDir, modFilePath)
	if !ok {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"ToggleMod", "拒绝切换受管 Mods 目录之外的文件: "+modFilePath)
		return fmt.Errorf("只能切换 Mods 目录内的 .jar 文件")
	}
	if _, err := os.Stat(curAbs); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}

	var newPath string
	if enable {
		if strings.HasSuffix(strings.ToLower(curAbs), disabledJarSuffix) {
			newPath = curAbs[:len(curAbs)-len(".disabled")]
		} else {
			return nil
		}
	} else {
		if strings.HasSuffix(strings.ToLower(curAbs), jarSuffix) {
			newPath = curAbs + ".disabled"
		} else {
			return nil
		}
	}

	// 改名目标也必须落在同一受管 mods 目录、且仍是受管 jar，防止借启用/禁用把文件
	// 挪出 mods 目录或挪成非受管文件（防御纵深：正常情况下仅后缀变化，父目录不变）。
	toAbs, ok := resolveManagedModPath(mcDir, newPath)
	if !ok || !sameManagedModDir(curAbs, toAbs) {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"ToggleMod", "拒绝把 Mod 改名到受管 Mods 目录之外: "+newPath)
		return fmt.Errorf("非法的 Mod 目标路径")
	}

	if err := os.Rename(curAbs, toAbs); err != nil {
		return fmt.Errorf("重命名失败: %v", err)
	}

	return nil
}

// ImportMod 导入 Mod 文件
func (a *App) ImportMod(versionID string) error {
	if versionID != "" {
		if strings.Contains(versionID, "..") || strings.Contains(versionID, "/") || strings.Contains(versionID, "\\") {
			return fmt.Errorf("版本ID包含非法字符")
		}
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "Mod 文件 (*.jar)", Pattern: "*.jar"},
		},
	})
	if err != nil || path == "" {
		return nil
	}

	mcDir := a.GetMinecraftDir()
	var modsDir string

	if a.isVersionIsolated() && versionID != "" {
		modsDir = filepath.Join(mcDir, "versions", versionID, "mods")
	} else {
		modsDir = filepath.Join(mcDir, "mods")
	}

	// 纵深防御：无论是否版本隔离，导入落点都必须解析在 .minecraft 内，
	// 防止 versionID / 配置异常把 jar 写到游戏目录之外。
	if _, ok := PathWithin(mcDir, modsDir); !ok {
		return fmt.Errorf("Mods 目录越界，拒绝导入: %s", modsDir)
	}
	// 0700 建目录；目录已存在但权限偏宽时也一并收权（MkdirAll 不会收权）。
	if err := ensurePrivateDir(modsDir); err != nil {
		return fmt.Errorf("创建 Mod 目录失败: %w", err)
	}

	// 用户手动导入的 jar 完全没有下载链的哈希 / 主机白名单背书，更要在落进
	// mods 目录前做静态扫描，挡掉本地双击“安装”的恶意 jar（critical 阻断）。
	if _, err := enforceModJarScan(path, "mod-import", filepath.Base(path)); err != nil {
		return fmt.Errorf("Mod 安全扫描失败: %w", err)
	}

	// 手动导入的文件名同样走 nameguard（挡控制字符 / 保留设备名 / 尾点等），
	// 且只接受 .jar（.zip / .jar.disabled 不允许经“导入 Mod”入口进入 mods 目录）。
	fileName, whyName := SafeModFileName(filepath.Base(path))
	if whyName != nameRejectNone || !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
		return fmt.Errorf("Mod 文件名无效: %s", describeNameReject(whyName))
	}
	// 与下载链一致：目录里已有大小写 / 尾点等价同名文件时改名避让，避免覆盖或
	// 与既有 Mod 在大小写不敏感卷上撞成同一文件。
	plannedName, collided, planErr := planModDestName(modsDir, fileName)
	if planErr != nil {
		return planErr
	}
	if collided {
		recordSecurityEvent("download", auditSeverityWarn, auditActionDetected,
			"mod-name-collision", "导入时发现同名 Mod，已改名避让: "+fileName+" -> "+plannedName)
	}
	fileName = plannedName
	destPath := filepath.Join(modsDir, fileName)

	// 统一走安全复制内核，替换旧的 os.Open + io.Copy + OpenFile(O_TRUNC)：
	// 源拒绝符号链接 / 特殊文件；LimitReader+1 有界复制（上限沿用下载链
	// maxDownloadBytes，stat 之后文件继续增长也会在多读 1 字节时被拦下，堵 TOCTOU）；
	// 目标写 0600 临时文件 + fsync + 原子 rename，杜绝跟随预置符号链接写穿与半截文件。
	if err := copyFileSecure(path, destPath, privateFilePerm, maxDownloadBytes); err != nil {
		return fmt.Errorf("复制 Mod 文件失败: %w", err)
	}

	return nil
}

// DeleteMod 删除 Mod 文件
func (a *App) DeleteMod(modFilePath string) error {
	mcDir := a.GetMinecraftDir()
	// 与 ToggleMod 同一收口：只能删除受管 mods 目录顶层的 .jar/.jar.disabled。
	// 旧实现 PathWithin(mcDir) 允许删除 .minecraft 内任意文件（saves 世界、版本库等）。
	targetAbs, ok := resolveManagedModPath(mcDir, modFilePath)
	if !ok {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"DeleteMod", "拒绝删除受管 Mods 目录之外的文件: "+modFilePath)
		return fmt.Errorf("只能删除 Mods 目录内的 .jar 文件")
	}
	if _, err := os.Stat(targetAbs); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}
	return os.Remove(targetAbs)
}

// downloadModItem 下载 Mod 文件
