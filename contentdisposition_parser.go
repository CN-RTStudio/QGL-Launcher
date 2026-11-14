package main

import ()

func (p *cdParser) skipOWS() {
	for !p.atEnd() {
		c := p.s[p.i]
		if c == ' ' || c == '\t' {
			p.i++
			continue
		}
		break
	}
}
func (p *cdParser) readToken() string {
	start := p.i
	for !p.atEnd() {
		c := p.s[p.i]
		if isTokenChar(c) {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i]
}
