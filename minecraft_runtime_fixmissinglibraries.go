package main

import (
	"fmt"
	"path/filepath"
)

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

func generateOfflineUUID(username string) string {
	data := "OfflinePlayer:" + username
	hash := NewUMFS([]byte(data)).Digest()
	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}

var crashKeywords = []string{
	"Crash report saved to", "This crash report has been saved to:",
	"Could not save crash report to", "Someone is closing me!",
	"Restarting Minecraft with command", "An exception was thrown, the game will display an error screen and halt.",
	"UNABLE TO LAUNCH", "Failed to start the Minecraft runtime",
	"Exception in thread", "java.lang.UnsatisfiedLinkError",
	"java.lang.NoClassDefFoundError", "java.lang.OutOfMemoryError",
	"Unable to launch", "java.lang.reflect.InvocationTargetException",
}
var logProgressKeywords = []struct {
	level   int
	keyword string
}{
	{2, "Setting user:"}, {3, "LWJGL Version:"}, {3, "lwjgl version"},
	{4, "OpenAL initialized"}, {4, "Starting up SoundSystem"},
	{5, "Created: "}, {5, "textures"}, {5, "-atlas"},
}
