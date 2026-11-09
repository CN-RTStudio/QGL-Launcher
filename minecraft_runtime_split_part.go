package main

import (
	"os"
	"path/filepath"
)

func localArtifactMissing(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return info.IsDir() || info.Size() == 0
}

// fixMissingLibraries 在启动前补齐版本清单要求、但本地缺失（或为空）的库与 Windows
// 本地库。它只复用版本安装阶段那条已审计的安全下载链：主机白名单在
// downloadVerifiedFile 内强制、相对路径走 SafeMavenRelPath 防 Zip Slip、SHA1 用清单
// 官方锚校验；本函数绝不新增任何旁路。已存在且非空的文件不重下（侧车复核仍在
// downloadVerifiedFile / verifyCachedFile 一侧，这里只为“缺失”场景补下载）。
func (a *App) fixMissingLibraries(mcDir string, versionJSON *VersionJSON) {
	if versionJSON == nil {
		return
	}
	winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
	libsDir := filepath.Join(mcDir, "libraries")

	fetchArtifact := func(art *LibArtifact, label string) {
		if art == nil {
			return
		}
		safeRel := SafeMavenRelPath(art.Path)
		if safeRel == "" {
			a.writeLog("补全库时跳过不安全路径: %s", art.Path)
			return
		}
		dest := filepath.Join(libsDir, filepath.FromSlash(safeRel))
		if !localArtifactMissing(dest) {
			return
		}
		a.emitProgress("downloading", filepath.Base(safeRel), 0, art.Size)
		if err := a.downloadVerifiedFile(rewriteLauncherURLToBMCL(art.URL), dest, art.SHA1, false); err != nil {
			a.writeLog("补全库文件失败(跳过): %s, %v", label, err)
		}
	}

	for i := range versionJSON.Libraries {
		lib := &versionJSON.Libraries[i]
		if !a.shouldIncludeLib(*lib) || lib.Downloads == nil {
			continue
		}
		fetchArtifact(lib.Downloads.Artifact, lib.Name)
		if lib.Natives != nil && lib.Downloads.Classifiers != nil {
			if nativeKey, ok := resolveWindowsNativeKey(lib.Natives, winEnv); ok {
				fetchArtifact(lib.Downloads.Classifiers[nativeKey], lib.Name+":"+nativeKey)
			}
		}
	}
}
