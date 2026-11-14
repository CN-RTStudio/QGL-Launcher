package main

import ()

func cdErr(code string) error { return &cdErrT{code: code} }
func CDReason(err error) string {
	if e, ok := err.(*cdErrT); ok {
		return e.code
	}
	return ""
}
