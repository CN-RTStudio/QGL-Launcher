package main

import (
	"fmt"
)

func mrpackReject(why, detail string) error {
	recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
		"mrpackguard", describeMrpackReject(why)+"："+detail)
	return fmt.Errorf("%s", describeMrpackReject(why))
}
