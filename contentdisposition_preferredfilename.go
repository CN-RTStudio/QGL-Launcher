package main

import ()

func (r *CDResult) PreferredFilename() string {
	if r == nil {
		return ""
	}
	if r.FilenameStar != "" {
		return r.FilenameStar
	}
	return r.Filename
}

type cdParser struct {
	s string
	i int
}

func (p *cdParser) atEnd() bool { return p.i >= len(p.s) }
