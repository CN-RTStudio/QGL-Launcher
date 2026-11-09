package main

import (
	"fmt"
	"strings"
)

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

func (a *App) isVersionIsolated() bool { return a.IsVersionIsolation() }
func sanitizePathComponent(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("无效的路径组件: %s", name)
	}
	return nil
}
