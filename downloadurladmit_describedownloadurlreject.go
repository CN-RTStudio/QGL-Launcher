package main

import ()

func describeDownloadURLReject(reason string) string {
	return rejectReasonText(reason, "URL 未通过安全校验", describeDownloadURLRejectTexts)
}
