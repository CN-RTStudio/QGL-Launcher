package main

import (
	"os/exec"
	"syscall"
)

func runInstaller(filePath string, isMSI bool) error {
	if err := validateInstallerPackage(filePath, isMSI); err != nil {
		recordSecurityEvent(auditCategoryInstaller, auditSeverityCritical, auditActionBlocked,
			"minecraft", "安装包执行前校验失败: "+err.Error())
		return err
	}
	if isMSI {
		cmd := exec.Command("msiexec", "/i", filePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}
	cmd := exec.Command("explorer", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
