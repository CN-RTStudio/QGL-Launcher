package main

func (s *boundedLineSplitter) Feed(chunk []byte) []string {
	if len(chunk) == 0 {
		return nil
	}
	var produced []string
	for len(chunk) > 0 {
		i := indexByte(chunk, '\n')
		if i < 0 {
			if line := s.absorbTrailing(chunk); line != "" {
				produced = append(produced, line)
			}
			break
		}
		if line, ok := s.finishLineAtNewline(chunk[:i]); ok {
			produced = append(produced, line)
		}
		chunk = chunk[i+1:]
	}
	return produced
}
