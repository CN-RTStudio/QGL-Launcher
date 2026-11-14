package main

import ()

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
