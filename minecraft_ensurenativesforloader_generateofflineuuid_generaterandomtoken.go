package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"time"

)

func generateRandomToken() string {
	now := time.Now().UnixNano()
	data := fmt.Sprintf("QGLToken%d%d", now, os.Getpid())
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%08x%04x%04x%04x%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// 崩溃检测关键字（参考PCL）
var crashKeywords = []string{
	"Crash report saved to",
	"This crash report has been saved to:",
	"Could not save crash report to",
	"Someone is closing me!",
	"Restarting Minecraft with command",
	"An exception was thrown, the game will display an error screen and halt.",
	"UNABLE TO LAUNCH",
	"Failed to start the Minecraft runtime",
	"Exception in thread",
	"java.lang.UnsatisfiedLinkError",
	"java.lang.NoClassDefFoundError",
	"java.lang.OutOfMemoryError",
	"Unable to launch",
	"java.lang.reflect.InvocationTargetException",
}

// 日志进度关键字（参考PCL的Watcher）
var logProgressKeywords = []struct {
	level  int
	keyword string
}{
	{2, "Setting user:"},
	{3, "LWJGL Version:"},
	{3, "lwjgl version"},
	{4, "OpenAL initialized"},
	{4, "Starting up SoundSystem"},
	{5, "Created: "},
	{5, "textures"},
	{5, "-atlas"},
}

// LaunchGame 启动 Minecraft 游戏，并检测窗口出现或崩溃
