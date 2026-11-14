package main

import ()

func (a *JvmArgsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *JvmArgsAudit) Describe() string {
	return describeReasonDetail("user_jvm_args.txt 未发现风险", a.Findings, 12)
}
