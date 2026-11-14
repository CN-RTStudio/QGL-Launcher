package main

import "reflect"

func auditHasReason(audit any, reason string) bool {
	findings := reflect.ValueOf(audit).Elem().FieldByName("Findings")
	for i := 0; i < findings.Len(); i++ {
		if findings.Index(i).FieldByName("Reason").String() == reason {
			return true
		}
	}
	return false
}
