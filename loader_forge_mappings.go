package main

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const maxMappingsDownloadBytes int64 = 1 << 30

func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

	r, err := zip.OpenReader(installerPath)
	if err != nil {
		a.writeLog("无法打开安装器（跳过 Mappings 检查）: %v", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	var mcVersion string
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				a.writeLog("读取 install_profile.json 失败(条目过大或损坏，跳过): %v", err)
				break
			}
			json.Unmarshal(data, &installProfile)

			if minecraftVal, ok := installProfile["minecraft"]; ok {
				if mv, ok := minecraftVal.(string); ok {
					mcVersion = mv
					a.writeLog("找到 mcVersion: %s", mcVersion)
				}
			}
			break
		}
	}

	if installProfile == nil || mcVersion == "" {
		a.writeLog("未找到 mcVersion（跳过 Mappings 检查）")
		return
	}
	if !isValidMCVersion(mcVersion) {
		a.writeLog("mcVersion 未通过版本格式白名单（跳过 Mappings 检查）: %s", mcVersion)
		return
	}

	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 data 字段（跳过 Mappings 检查）")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 MOJMAPS 字段（跳过 Mappings 检查）")
		return
	}

	clientValue, ok := mojmapsData["client"].(string)
	if !ok || clientValue == "" {
		a.writeLog("未找到 MOJMAPS.client 字段（跳过 Mappings 检查）")
		return
	}

	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	// 坐标与扩展名来自不可信的安装器 JSON，不能再用 Split 后原样拼 filepath.Join，
	// 否则 ".." 段 / 分隔符 / 带穿越的扩展名会把 mappings 写到 libraries 之外。
	// 统一走严格白名单推导，并强制结果落在 <mcDir>/libraries 内。
	targetPath, ok := SafeMojmapsMappingsPath(mcDir, originalName, extension)
	if !ok {
		a.writeLog("MOJMAPS.client 坐标或扩展名未通过路径白名单（跳过 Mappings 检查）")
		return
	}

	a.writeLog("目标路径: %s", targetPath)

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		a.writeLog("无法读取/解析原版版本 JSON: %v", err)
		return
	}

	downloads, _ := rawJSON["downloads"].(map[string]interface{})
	if downloads == nil {
		a.writeLog("未找到 downloads 字段")
		return
	}

	clientMappings, _ := downloads["client_mappings"].(map[string]interface{})
	if clientMappings == nil {
		a.writeLog("未找到 client_mappings 字段")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		a.writeLog("未找到 client_mappings URL")
		return
	}

	expectedSHA1, _ := clientMappings["sha1"].(string)
	expectedSHA1 = strings.ToLower(strings.TrimSpace(expectedSHA1))

	if expectedSHA1 != "" {
		if info, statErr := os.Stat(targetPath); statErr == nil && info.Size() > 0 {
			if existingSHA1, hashErr := fileSHA1Hex(targetPath); hashErr == nil && existingSHA1 == expectedSHA1 {
				a.writeLog("Mappings 文件已存在且 SHA1 校验通过: %s", targetPath)
				return
			}
			a.writeLog("Mappings 文件已存在但 SHA1 不符，重新下载: %s", targetPath)
		}
	}

	// 安全验证：只允许 HTTPS
	if !isHTTPSURL(mappingsURL) {
		a.writeLog("跳过不安全的下载 URL（非 HTTPS）: %s", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	a.writeLog("使用 Go 原生 HTTP 下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 这里是手写流式下载（os.OpenFile 直接落盘），由本处显式确保目录 0700 并收权。
	if err := ensurePrivateDir(filepath.Dir(targetPath)); err != nil {
		a.writeLog("创建目标目录失败: %v", err)
		return
	}

	// 安全修复：使用 Go 原生 HTTP 下载，替代 PowerShell 命令，防止命令注入
	client := safeHTTPClient()
	req, err := http.NewRequest("GET", mappingsURL, nil)
	if err != nil {
		a.writeLog("创建下载请求失败: %v", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		a.writeLog("下载失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.writeLog("下载失败: HTTP %d", resp.StatusCode)
		return
	}

	out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		a.writeLog("创建目标文件失败: %v", err)
		return
	}
	defer out.Close()

	limited := io.LimitReader(resp.Body, maxMappingsDownloadBytes+1)
	n, copyErr := io.Copy(out, limited)
	if copyErr != nil || n > maxMappingsDownloadBytes {
		a.writeLog("mappings 文件超过 %d 字节上限，中止下载", maxMappingsDownloadBytes)
		os.Remove(targetPath)
		return
	}

	fileInfo, statErr := os.Stat(targetPath)
	if statErr != nil {
		a.writeLog("下载后验证文件失败: %v", statErr)
		return
	}

	if fileInfo.Size() == 0 {
		a.writeLog("下载的文件为空！删除空文件")
		os.Remove(targetPath)
		return
	}

	if expectedSHA1 != "" {
		actualSHA1, hashErr := fileSHA1Hex(targetPath)
		if hashErr != nil || actualSHA1 != expectedSHA1 {
			a.writeLog("Mappings SHA1 校验失败（期望 %s，实际 %s），删除半可信文件", expectedSHA1, actualSHA1)
			os.Remove(targetPath)
			return
		}
	}

	a.writeLog("Mappings 下载成功! 文件大小: %d 字节, 路径: %s", fileInfo.Size(), targetPath)
}

func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("读取 install_profile.json 失败(条目过大或损坏，跳过): %v\n", err)
				break
			}
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	if !isValidMCVersion(mcVersion) {
		fmt.Printf("mcVersion 未通过版本格式白名单（跳过 Mappings 下载）: %s\n", mcVersion)
		return
	}

	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
		return
	}

	mcpVersion, ok := mojmapsData["version"].(string)
	if !ok || mcpVersion == "" {
		fmt.Printf("未找到 MOJMAPS.version 字段（跳过 Mappings 下载）\n")
		return
	}

	fmt.Printf("检测到 Forge MOJMAPS: %s\n", mcpVersion)

	targetPath, ok := SafeMappingsVersionPath(mcDir, mcpVersion)
	if !ok {
		fmt.Printf("MOJMAPS.version 未通过落盘路径白名单（跳过 Mappings 下载）: %s\n", mcpVersion)
		return
	}

	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		fmt.Printf("无法读取/解析原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
		return
	}

	downloads, ok := rawJSON["downloads"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 downloads 字段（跳过 Mappings 下载）\n")
		return
	}

	clientMappings, ok := downloads["client_mappings"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 client_mappings 字段（跳过 Mappings 下载）\n")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		fmt.Printf("未找到 client_mappings URL（跳过 Mappings 下载）\n")
		return
	}

	if !isHTTPSURL(mappingsURL) {
		fmt.Printf("跳过不安全的下载 URL（非 HTTPS）: %s\n", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	tempPath := targetPath + ".tmp"
	_ = os.Remove(tempPath)
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFileBounded(mappingsURL, tempPath, false, maxMappingsDownloadBytes); err != nil {
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	expectedSHA1, _ := clientMappings["sha1"].(string)
	expectedSHA1 = strings.ToLower(strings.TrimSpace(expectedSHA1))
	if expectedSHA1 != "" {
		actualSHA1, hashErr := fileSHA1Hex(tempPath)
		if hashErr != nil || actualSHA1 != expectedSHA1 {
			fmt.Printf("Mappings SHA1 校验失败（期望 %s，实际 %s），删除下载文件\n", expectedSHA1, actualSHA1)
			os.Remove(tempPath)
			return
		}
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		// launcher_profiles.json 是启动器状态文件，有界原子私有写防半截写与符号链接写穿；
		// 序列化错误也不再被丢弃。
		if err := writePrivateJSON(profilesPath, profiles); err != nil {
			fmt.Printf("创建 launcher_profiles.json 失败: %v\n", err)
		}
	}
}

func (a *App) getVersionFolderList(mcDir string) map[string]bool {
	versionsDir := filepath.Join(mcDir, "versions")
	result := map[string]bool{}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() {
			result[entry.Name()] = true
		}
	}

	return result
}

func (a *App) runForgeInstaller(installerPath string, mcDir string) error {
	a.writeLog("===== 开始运行 ForgeInstaller =====")

	a.ensureForgeMappings(installerPath, mcDir)

	bbInstallerPath, err := a.extractForgeInstaller()
	if err != nil {
		a.writeLog("提取 ForgeInstaller 失败: %v", err)
		return err
	}
	a.writeLog("ForgeInstaller 路径: %s", bbInstallerPath)
	a.writeLog("Forge 安装器路径: %s", installerPath)

	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		a.writeLog("选择 Java 失败: %v", err)
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	a.writeLog("使用 Java: %s (版本: %s, 主版本: %d)", javaEntry.Path, javaEntry.Version, javaEntry.MajorVer)

	classpath := bbInstallerPath + ";" + installerPath

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, "-cp", classpath, "com.bangbang93.ForgeInstaller", mcDir)

	a.writeLog("完整命令: %s %s", javaEntry.Path, strings.Join(args, " "))

	// 启动前对安装器 JVM 做目标审计：java 可执行、工作目录、绝对 classpath 的目录归属
	// （bbInstaller / installer 各自的父目录 + mcDir）、主类与程序参数，阻止任何指向
	// UNC / 目录穿越 / 允许目录之外的 jar/classpath。
	forgeRoots := []string{mcDir, filepath.Dir(bbInstallerPath), filepath.Dir(installerPath)}
	forgeAudit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaEntry.Path,
		WorkDir:      mcDir,
		Classpath:    []string{bbInstallerPath, installerPath},
		MainClass:    "com.bangbang93.ForgeInstaller",
		ProgramArgs:  []string{mcDir},
		AllowedRoots: forgeRoots,
	})
	if forgeAudit.HasCritical() {
		return fmt.Errorf("Forge 安装器启动审计未通过: %s", forgeAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Forge 安装器本身是个独立 JVM：不下发净化环境就会继承
	// JAVA_TOOL_OPTIONS 一族，绕过 JVM 参数过滤注入 javaagent。
	a.applySanitizedJVMEnv(cmd, "ForgeInstaller", nil)

	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	a.writeLog("----- ForgeInstaller 输出开始 -----")
	if outputStr != "" {
		for _, line := range strings.Split(outputStr, "\n") {
			a.writeLog("  %s", line)
		}
	} else {
		a.writeLog("  (无输出)")
	}
	a.writeLog("----- ForgeInstaller 输出结束 -----")
	if runErr != nil {
		a.writeLog("进程退出错误: %v", runErr)
	}

	lines := strings.Split(outputStr, "\n")
	var lastLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			lastLines = append(lastLines, line)
		}
	}

	foundTrue := false
	checkCount := 4
	if len(lastLines) < checkCount {
		checkCount = len(lastLines)
	}
	for _, line := range lastLines[len(lastLines)-checkCount:] {
		if line == "true" {
			foundTrue = true
			break
		}
	}

	if foundTrue {
		a.writeLog("检测到安装器成功标志 'true'，安装成功")
		return nil
	}

	a.writeLog("未检测到安装器成功标志 'true'，安装失败")

	if runErr != nil {
		errMsg := fmt.Errorf("Forge 安装器运行失败\nJava: %s (v%d)\n错误: %v\n\n完整输出:\n%s",
			javaEntry.Path, javaEntry.MajorVer, runErr, outputStr)
		a.writeLog("Forge 安装最终失败: %v", errMsg)
		return errMsg
	}

	errMsg := fmt.Errorf("Forge 安装器未返回成功标志\nJava: %s (v%d)\n\n完整输出:\n%s",
		javaEntry.Path, javaEntry.MajorVer, outputStr)
	a.writeLog("Forge 安装最终失败: %v", errMsg)
	return errMsg
}

func (a *App) findNewVersionFolder(mcDir string, oldVersions map[string]bool, mcVersion string, loaderType string) string {
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() || oldVersions[entry.Name()] {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	return ""
}

func fileSHA1Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
