package main

import "testing"

func TestZBNormalArchive(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{})
	if safe, _ := a.ZBAuditEntry(ZBEntry{CompressedSize: 1000, UncompressedSize: 2000}, 2000); !safe {
		t.Fatal("normal modest ratio entry should pass")
	}
	if a.ZBSeen() != 1 || a.ZBTotal() != 2000 {
		t.Fatal("accepted entry must be accounted")
	}
}

func TestZBEntryTooLarge(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{MaxEntryBytes: 1024})
	_, fs := a.ZBAuditEntry(ZBEntry{CompressedSize: 512, UncompressedSize: 2048}, 2048)
	if !ZBHasReason(fs, ZBReasonEntryTooLarge) {
		t.Fatalf("oversized entry must flag: %v", fs)
	}
	if a.ZBSeen() != 0 {
		t.Fatal("rejected entry must not be accounted")
	}
}

func TestZBRatioTooHigh(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{MaxRatio: 10})
	_, fs := a.ZBAuditEntry(ZBEntry{CompressedSize: 1, UncompressedSize: 100000}, 100000)
	if !ZBHasReason(fs, ZBReasonRatioTooHigh) {
		t.Fatalf("extreme ratio bomb must flag: %v", fs)
	}
}

func TestZBZeroCompressedNonzeroOut(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{})
	_, fs := a.ZBAuditEntry(ZBEntry{CompressedSize: 0, UncompressedSize: 100}, 100)
	if !ZBHasReason(fs, ZBReasonRatioTooHigh) {
		t.Fatalf("0 compressed bytes yielding data must flag as infinite ratio: %v", fs)
	}
}

func TestZBEmptyEntryOK(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{})
	if safe, _ := a.ZBAuditEntry(ZBEntry{CompressedSize: 0, UncompressedSize: 0}, 0); !safe {
		t.Fatal("empty dir/file entry should pass")
	}
}

func TestZBTotalBudget(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{MaxTotalBytes: 1000, MaxEntryBytes: 1000000, MaxRatio: 1000000})
	if safe, _ := a.ZBAuditEntry(ZBEntry{600, 600}, 600); !safe {
		t.Fatal("first entry should pass")
	}
	_, fs := a.ZBAuditEntry(ZBEntry{600, 600}, 600)
	if !ZBHasReason(fs, ZBReasonTotalTooLarge) {
		t.Fatalf("cumulative overflow must flag: %v", fs)
	}
}

func TestZBTooManyEntries(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{MaxEntries: 2})
	a.ZBAuditEntry(ZBEntry{1, 1}, 1)
	a.ZBAuditEntry(ZBEntry{1, 1}, 1)
	_, fs := a.ZBAuditEntry(ZBEntry{1, 1}, 1)
	if !ZBHasReason(fs, ZBReasonTooManyEntries) {
		t.Fatalf("third entry beyond entry cap must flag: %v", fs)
	}
}

func TestZBDeclaredMismatch(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{})
	_, fs := a.ZBAuditEntry(ZBEntry{10, 100}, 99)
	if !ZBHasReason(fs, ZBReasonDeclaredMismatch) {
		t.Fatalf("declared/stream size mismatch must flag: %v", fs)
	}
}

func TestZBDiskBudget(t *testing.T) {
	a := ZBNewAuditor(ZBLimits{DiskFreeBytes: 500, MaxEntryBytes: 1 << 30})
	_, fs := a.ZBAuditEntry(ZBEntry{1, 600}, 600)
	if !ZBHasReason(fs, ZBReasonDiskBudget) {
		t.Fatalf("expansion beyond free disk must flag: %v", fs)
	}
}
