package main

import ()

func (r *classReader) u1() int {
	if !r.ok || r.off+1 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])
	r.off++
	return v
}

func (r *classReader) u2() int {
	if !r.ok || r.off+2 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<8 | int(r.b[r.off+1])
	r.off += 2
	return v
}

func (r *classReader) u4() int {
	if !r.ok || r.off+4 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<24 | int(r.b[r.off+1])<<16 | int(r.b[r.off+2])<<8 | int(r.b[r.off+3])
	r.off += 4
	return v
}
