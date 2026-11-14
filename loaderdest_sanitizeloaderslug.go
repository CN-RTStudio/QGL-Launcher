package main

import (
	"strings"
)

func sanitizeLoaderSlug(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	prevSep := true
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevSep = false
		case r == '-' || r == '_' || r == '.':
			if !prevSep {
				b.WriteRune(r)
				prevSep = true
			}
		default:
			if !prevSep {
				b.WriteByte('_')
				prevSep = true
			}
		}
	}
	slug := strings.Trim(b.String(), "._-")
	if len(slug) > maxLoaderSlugLen {
		slug = strings.Trim(slug[:maxLoaderSlugLen], "._-")
	}
	return slug
}
