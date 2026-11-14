package main

import (
	"strings"
)

func validDownloadHostLabels(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	if len(labels) < 2 {
		return false
	}
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if last[i] >= '0' && last[i] <= '9' {
			return false
		}
	}
	return true
}
