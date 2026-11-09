package main

// sessionjournal_test.go —— 会话台账纯函数单测。
//
// 只测不依赖 App/网络的纯函数：sanitizeSessionRecord 收口、decideSessionAppend
// 上限淘汰、sessionDurationSec 计算、loadSessionJournal 脏文件容错。
// （App 绑定层依赖 Wails runtime，单测不覆盖，靠 build/vet 保证编译正确。）

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeSessionRecord(t *testing.T) {
	now := time.Now().Format(time.RFC3339)
	valid := SessionRecord{
		VersionID: "1.20.1",
		Pid:       1234,
		StartedAt: now,
		Outcome:   SessionOutcomeRunning,
	}
	if err := sanitizeSessionRecord(&valid); err != nil {
		t.Fatalf("合法记录被拒: %v", err)
	}
	// 控制字符 / 空白版本 ID 应被拒。
	badVersion := SessionRecord{VersionID: "\x00evil\n", Pid: 1, StartedAt: now, Outcome: SessionOutcomeOk}
	if err := sanitizeSessionRecord(&badVersion); err == nil {
		t.Fatal("非法版本ID未被拒绝")
	}
	// 非法结局应被拒。
	badOutcome := SessionRecord{VersionID: "1.20.1", Pid: 1, StartedAt: now, Outcome: "exploit"}
	if err := sanitizeSessionRecord(&badOutcome); err == nil {
		t.Fatal("非法结局未被拒绝")
	}
	// PID <= 0 应被拒。
	badPid := SessionRecord{VersionID: "1.20.1", Pid: 0, StartedAt: now, Outcome: SessionOutcomeOk}
	if err := sanitizeSessionRecord(&badPid); err == nil {
		t.Fatal("非法PID未被拒绝")
	}
	// 详情超长应被截断（而非拒绝/膨胀）。
	longDetail := SessionRecord{
		VersionID: "1.20.1", Pid: 1, StartedAt: now, Outcome: SessionOutcomeCrash,
		Detail: strings.Repeat("A", maxSessionDetailBytes+1024),
	}
	if err := sanitizeSessionRecord(&longDetail); err != nil {
		t.Fatalf("超长详情被拒（应截断）: %v", err)
	}
	if len(longDetail.Detail) > maxSessionDetailBytes {
		t.Fatalf("详情未截断: %d", len(longDetail.Detail))
	}
}

func TestDecideSessionAppendCaps(t *testing.T) {
	var base []SessionRecord
	for i := 0; i < 5; i++ {
		base = append(base, SessionRecord{VersionID: "v", Pid: i + 1, StartedAt: "t", Outcome: SessionOutcomeOk})
	}
	next := SessionRecord{VersionID: "v", Pid: 99, StartedAt: "t2", Outcome: SessionOutcomeRunning}
	out := decideSessionAppend(base, next, 3)
	if len(out) != 3 {
		t.Fatalf("期望最多 3 条，得到 %d", len(out))
	}
	if out[0].Pid != 4 || out[len(out)-1].Pid != 99 {
		t.Fatalf("淘汰最旧失败: %+v", out)
	}
	// 默认上限（<=0 参数）也生效。
	out2 := decideSessionAppend(base, next, 0)
	if len(out2) != 6 {
		t.Fatalf("默认上限应为 6 条，得到 %d", len(out2))
	}
}

func TestSessionDurationSec(t *testing.T) {
	start := time.Now().Add(-2 * time.Minute).Format(time.RFC3339)
	end := time.Now().Format(time.RFC3339)
	if d := sessionDurationSec(start, end); d < 119 || d > 121 {
		t.Fatalf("2 分钟时长计算异常: %d", d)
	}
	if d := sessionDurationSec("not-a-time", end); d != 0 {
		t.Fatalf("非法时间应返回 0，得到 %d", d)
	}
	// 结束早于开始 → 0（防负值）。
	if d := sessionDurationSec(end, start); d != 0 {
		t.Fatalf("倒挂时长应返回 0，得到 %d", d)
	}
}

func TestLoadSessionJournalToleratesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sessionJournalFileName())
	// 不存在 → 空，无错误（返回 nil 列表）。
	if recs := loadSessionJournal(path); recs != nil {
		t.Fatalf("文件不存在应返回 nil，得到 %+v", recs)
	}
	// 脏 JSON → 空列表。
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if recs := loadSessionJournal(path); recs != nil {
		t.Fatalf("脏 JSON 应返回 nil，得到 %+v", recs)
	}
	// 合法 JSON 但带一条非法记录 → 只保留合法记录。
	payload := `[
	  {"versionId":"1.20.1","pid":1,"startedAt":"2026-01-01T00:00:00Z","outcome":"ok"},
	  {"versionId":"","pid":2,"startedAt":"2026-01-01T00:00:00Z","outcome":"crash"}
	]`
	if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	recs := loadSessionJournal(path)
	if len(recs) != 1 || recs[0].Pid != 1 {
		t.Fatalf("脏记录未丢弃: %+v", recs)
	}
}

func TestSessionJournalFileNameStable(t *testing.T) {
	if n := sessionJournalFileName(); n != "session-journal.json" {
		t.Fatalf("台账文件名不稳定: %s", n)
	}
}
