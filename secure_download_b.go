package main

import (
	"fmt"
	"net/http"
)

func secureDownloadCheckRedirect(req *http.Request, via []*http.Request, inner func(*http.Request, []*http.Request) error) error {
	if inner != nil {
		if err := inner(req, via); err != nil {
			return err
		}
	}
	if err := safeCheckRedirect(req, via); err != nil {
		return err
	}
	if len(via) == 0 {
		return nil
	}
	chain, err := newRedirectChain(via[0].URL.String(), defaultRedirectLimits())
	if err != nil {
		return fmt.Errorf("%w: 无法记录入口 URL", errSecureDownloadBadRedirect)
	}
	for _, hop := range via[1:] {
		if ok, reason := chain.Decide(hop.URL.String(), nil); !ok {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
				"secure-download", "重定向中间跳被拒绝: "+reason+" -> "+hop.URL.String())
			return fmt.Errorf("%w: %s", errSecureDownloadBadRedirect, reason)
		}
	}
	if ok, reason := chain.Decide(req.URL.String(), nil); !ok {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"secure-download", "重定向目标被拒绝: "+reason+" -> "+req.URL.String())
		return fmt.Errorf("%w: %s", errSecureDownloadBadRedirect, reason)
	}
	return nil
}
