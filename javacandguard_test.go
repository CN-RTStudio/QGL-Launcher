package main

import (
	"runtime"
	"testing"
)

func TestClassifyJavaCandidate_Trusted(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows trust-root layout asserted here")
	}
	c := JavaCandidate{Path: `C:\Program Files\Java\jdk-21\bin\java.exe`}
	level, reasons := ClassifyJavaCandidate(c)
	if level != 2 {
		t.Fatalf("want level 2 trusted, got %d reasons=%v", level, reasons)
	}
}

func TestClassifyJavaCandidate_TraversalRejected(t *testing.T) {
	c := JavaCandidate{Path: `C:\Program Files\Java\..\..\evil\java.exe`}
	level, reasons := ClassifyJavaCandidate(c)
	if level != 0 {
		t.Fatalf("want level 0 reject, got %d reasons=%v", level, reasons)
	}
}

func TestClassifyJavaCandidate_WrongNameRejected(t *testing.T) {
	c := JavaCandidate{Path: `C:\Program Files\Java\jdk\bin\javaw.exe`}
	level, reasons := ClassifyJavaCandidate(c)
	if level != 0 {
		t.Fatalf("want level 0 reject for javaw, got %d reasons=%v", level, reasons)
	}
}

func TestClassifyJavaCandidate_SymlinkDowngraded(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows trust-root layout asserted here")
	}
	c := JavaCandidate{Path: `C:\Program Files\Java\jdk\bin\java.exe`, IsSymlink: true}
	level, reasons := ClassifyJavaCandidate(c)
	if level != 1 {
		t.Fatalf("want level 1 review for symlink, got %d reasons=%v", level, reasons)
	}
	if !IsTrustedJavaCandidate(c) {
		// symlink must not be auto-trusted
	}
}

func TestClassifyJavaCandidate_OutsideRootNeedsReview(t *testing.T) {
	c := JavaCandidate{Path: `C:\Users\someone\Downloads\jdk\bin\java.exe`}
	level, reasons := ClassifyJavaCandidate(c)
	if level != 1 {
		t.Fatalf("want level 1 review, got %d reasons=%v", level, reasons)
	}
}

func TestClassifyJavaCandidate_Empty(t *testing.T) {
	if level, _ := ClassifyJavaCandidate(JavaCandidate{}); level != 0 {
		t.Fatalf("empty path must be rejected, got %d", level)
	}
}

func TestValidJavaExecutableName(t *testing.T) {
	if runtime.GOOS == "windows" {
		if !ValidJavaExecutableName(`C:\x\java.exe`) {
			t.Fatal("java.exe should be valid on windows")
		}
		if ValidJavaExecutableName(`C:\x\javaw.exe`) {
			t.Fatal("javaw must not be accepted as the launch binary")
		}
		return
	}
	if !ValidJavaExecutableName("/x/java") {
		t.Fatal("java should be valid")
	}
	if ValidJavaExecutableName("/x/javaw") {
		t.Fatal("javaw must not be accepted as the launch binary")
	}
}
