package main

// PreferredFilename 按 RFC 6267 优先返回 filename*，否则 filename；都没有返回空。
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
func (p *cdParser) peek() byte {
	if p.atEnd() {
		return 0
	}
	return p.s[p.i]
}
func (p *cdParser) next() byte {
	if p.atEnd() {
		return 0
	}
	c := p.s[p.i]
	p.i++
	return c
}
