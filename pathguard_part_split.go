package main

import (
	"path/filepath"
	"strings"
)

func SafeSimpleName(name string) string {
	if name == "" || len(name) > 256 {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		return ""
	}
	if !validateSafeSegment(name) {
		return ""
	}
	return name
}
func SafeMojmapsMappingsPath(mcDir, coord, ext string) (string, bool) {
	parts := strings.Split(coord, ":")
	if len(parts) != 3 {
		return "", false
	}
	groupSegs := strings.Split(parts[0], ".")
	if len(groupSegs) == 0 {
		return "", false
	}
	relElems := make([]string, 0, len(groupSegs)+4)
	relElems = append(relElems, "libraries")
	for _, g := range groupSegs {
		gs := SafeSimpleName(g)
		if gs == "" {
			return "", false
		}
		relElems = append(relElems, gs)
	}
	artifact := SafeSimpleName(parts[1])
	version := SafeSimpleName(parts[2])
	if artifact == "" || version == "" {
		return "", false
	}
	if !safeMappingsExt(ext) {
		return "", false
	}
	relElems = append(relElems, artifact, version, artifact+"-"+version+"-mappings."+ext)
	target := filepath.Join(mcDir, filepath.Join(relElems...))
	if !PathWithinRoot(target, filepath.Join(mcDir, "libraries")) {
		return "", false
	}
	return target, true
}
