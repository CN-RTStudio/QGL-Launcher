package main

import "fmt"

type launchGateAudit interface {
	Blocking() bool
	HasWarnings() bool
	Describe() string
}

func (a *App) gateLaunchSecurityStop(logPrefix, errPrefix string, au launchGateAudit) error {
	if !au.Blocking() {
		return nil
	}
	a.writeSecurityLog(logPrefix + au.Describe())
	return fmt.Errorf("%s: %s", errPrefix, au.Describe())
}

func (a *App) gateLaunchAudit(category, errLabel, warnLabel, target string, au launchGateAudit) error {
	if au.Blocking() {
		recordSecurityEvent(category, auditSeverityCritical, auditActionBlocked, au.Describe(), target)
		return fmt.Errorf("%s校验失败，拒绝启动: %s", errLabel, au.Describe())
	}
	if au.HasWarnings() {
		a.writeLog("%s告警: %s", warnLabel, au.Describe())
	}
	return nil
}
