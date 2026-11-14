package main

import ()

func auditManifestArtifact(field string, checkRelPath bool, art *LibArtifact, hosts map[string]bool) []ManifestFinding {
	if art == nil {
		return nil
	}
	var out []ManifestFinding
	if checkRelPath {
		if f := auditManifestRelPath(field+".path", art.Path); f != nil {
			out = append(out, *f)
		}
	}
	if f := auditManifestURL(field+".url", art.URL, hosts); f != nil {
		out = append(out, *f)
	}
	if f := auditManifestHash(field+".sha1", art.SHA1); f != nil {
		out = append(out, *f)
	}
	return out
}

// auditVersionManifest 对整份版本 JSON 做安全审计，返回全部问题（critical/warn）。
// 迭代数量有界，避免恶意超大清单把审计本身拖成 DoS。
