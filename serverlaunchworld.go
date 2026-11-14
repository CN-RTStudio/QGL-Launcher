package main

import (
	"fmt"
	"strings"
)

func (a *App) auditWorldForLaunch(serverDir string) error {
	worldName, worldNameSet, worldNameErr := readWorldLevelName(serverDir)
	if worldNameErr != nil {
		return worldNameErr
	}
	if worldNameSet {
		worldAudit, err := AuditWorldPath(serverDir, worldName)
		if err != nil {
			return err
		}
		if worldAudit.Blocking() {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
				describeWorldPathAudit(worldAudit), serverDir)
			return fmt.Errorf("世界目录校验失败，拒绝启动: %s", describeWorldPathAudit(worldAudit))
		}
		if len(worldAudit.Warnings) > 0 {
			a.writeLog("世界目录告警: %s", strings.Join(worldAudit.Warnings, "；"))
		}
	}

	if worldNameSet {
		worldAudit, _ := AuditWorldPath(serverDir, worldName)
		if worldAudit.Present && !worldAudit.Symlink {
			datapackAudit, err := AuditWorldDatapacks(worldAudit.Path)
			if err != nil {
				return err
			}
			if datapackAudit.Blocking() {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
					datapackAudit.Describe(), worldAudit.Path)
				return fmt.Errorf("数据包目录校验失败，拒绝启动: %s", datapackAudit.Describe())
			}
			if len(datapackAudit.Findings) > 0 {
				a.writeLog("数据包告警: %s", datapackAudit.Describe())
			}
			playerAudit, err := AuditWorldPlayerData(worldAudit.Path)
			if err != nil {
				return err
			}
			if playerAudit.Blocking() {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
					playerAudit.Describe(), worldAudit.Path)
				return fmt.Errorf("玩家数据目录校验失败，拒绝启动: %s", playerAudit.Describe())
			}
			if playerAudit.HasWarnings() {
				a.writeLog("玩家数据告警: %s", playerAudit.Describe())
			}
			regionAudit, regionErr := AuditWorldRegions(worldAudit.Path)
			if regionErr != nil {
				return regionErr
			}
			if regionAudit.Blocking() {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
					regionAudit.Describe(), worldAudit.Path)
				return fmt.Errorf("世界区域文件校验失败，拒绝启动: %s", regionAudit.Describe())
			}
			if regionAudit.HasWarnings() {
				a.writeLog("世界区域文件告警: %s", regionAudit.Describe())
			}
		}
	}
	return nil
}
