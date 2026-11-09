package main

import (
	"encoding/json"
	"os"
)

func auditDedupKey(category, action, source, detail string) string {
	// detail 只取前 96 个字符参与去重：路径前缀 / 主机名相同就算同一类事件，
	// 末尾变化的字节数 / 条目名不影响聚合判定。
	key := category + "\x00" + action + "\x00" + source + "\x00"
	runes := []rune(detail)
	if len(runes) > 96 {
		key += string(runes[:96])
	} else {
		key += detail
	}
	return key
}

// pushRing 以"新事件在末尾、超容从头丢弃"的方式维护定长环形缓冲。
func (s *securityAudit) pushRing(e SecurityEvent) {
	if len(s.ring) >= auditRingCap {
		copy(s.ring, s.ring[1:])
		s.ring[len(s.ring)-1] = e
		return
	}
	s.ring = append(s.ring, e)
}

// appendLineLocked 把一条事件以 JSONL 形式追加到文件，并在超限时轮转。
// 调用方必须持有 s.mu。任何 IO 错误都直接返回，由上层吞掉（审计不阻塞主流程）。
func (s *securityAudit) appendLineLocked(e SecurityEvent) error {
	if !s.initialized {
		return nil
	}
	if s.fileSize >= auditMaxFileBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// 每次追加前再做一次非普通文件检查：init 之后若有人把审计路径换成符号链接，
	// 这里在 O_APPEND（会跟随链接）之前拦下，防止写穿到链接目标。
	if err := rejectNonRegular(s.filePath); err != nil {
		return err
	}
	f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, privateFilePerm)
	if err != nil {
		return err
	}
	n, err := f.Write(line)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.fileSize += int64(n)
	return nil
}

// rotateLocked 把当前日志改名归档，新事件从空文件重新开始写。
// 只保留一份 .1 归档：再次轮转时旧 .1 直接删除，避免无限堆积。
func (s *securityAudit) rotateLocked() error {
	archive := s.filePath + auditLogArchiveSuffix
	if _, err := os.Lstat(s.filePath); err != nil {
		if os.IsNotExist(err) {
			s.fileSize = 0
			return nil
		}
		return err
	}
	// 归档目标若已存在（含被人预埋的符号链接），先删链接本身再改名。
	if _, err := os.Lstat(archive); err == nil {
		if rmErr := os.Remove(archive); rmErr != nil {
			return rmErr
		}
	}
	if err := os.Rename(s.filePath, archive); err != nil {
		return err
	}
	s.fileSize = 0
	return nil
}
