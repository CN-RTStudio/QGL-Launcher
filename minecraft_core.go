package main

import "syscall"

var (
	user32DLL           = syscall.NewLazyDLL("user32.dll")
	kernel32DLL         = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows     = user32DLL.NewProc("EnumWindows")
	procGetClassName    = user32DLL.NewProc("GetClassNameA")
	procGetWindowText   = user32DLL.NewProc("GetWindowTextA")
	procGetWindowPID    = user32DLL.NewProc("GetWindowThreadProcessId")
	procOpenProcess     = kernel32DLL.NewProc("OpenProcess")
	procGetProcessTimes = kernel32DLL.NewProc("GetProcessTimes")
	procCloseHandle     = kernel32DLL.NewProc("CloseHandle")
)

type MCVersion struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}
type VersionManifest struct {
	Latest struct {
		Release  string `json:"release"`
		Snapshot string `json:"snapshot"`
	} `json:"latest"`
	Versions []MCVersionInfo `json:"versions"`
}
type MCVersionInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	ReleaseTime string `json:"releaseTime"`
}
