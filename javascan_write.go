package main

import ()

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n += int64(len(p))
	remain := w.max + 1 - int64(w.buf.Len())
	if remain > 0 {
		if int64(len(p)) < remain {
			remain = int64(len(p))
		}
		w.buf.Write(p[:remain])
	}
	return len(p), nil
}
