package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func envHasReason(audit EnvHijackAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestEnvCleanScript(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "#!/bin/sh\nJAVA_HOME=/usr/lib/jvm/java-21\nexec java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("clean script reported: %s", audit.Describe())
	}
}

func TestEnvMissingDirectory(t *testing.T) {
	audit := AuditServerEnvironmentHijack(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() || !envHasReason(audit, envReasonMissing) {
		t.Fatalf("missing dir must block: %s", audit.Describe())
	}
}

func TestEnvLDPreloadBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "export LD_PRELOAD=/tmp/evil.so\nexec java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !audit.Blocking() || !envHasReason(audit, envReasonPreload) {
		t.Fatalf("LD_PRELOAD must block: %s", audit.Describe())
	}
}

func TestEnvDyldInsertBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "DYLD_INSERT_LIBRARIES=./evil.dylib java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonPreload) {
		t.Fatalf("DYLD insert not flagged: %s", audit.Describe())
	}
}

func TestEnvClasspathBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "run.bat", "SET CLASSPATH=extra.jar\r\njava -jar server.jar\r\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !audit.Blocking() || !envHasReason(audit, envReasonClasspath) {
		t.Fatalf("CLASSPATH must block: %s", audit.Describe())
	}
}

func TestEnvJavaToolOptionsAgentBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "export JAVA_TOOL_OPTIONS=-javaagent:/tmp/evil.jar\nexec java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonJVMAgent) || !audit.Blocking() {
		t.Fatalf("agent injection must block: %s", audit.Describe())
	}
}

func TestEnvJavaOptionsWarning(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "export _JAVA_OPTIONS=-Xmx4G\nexec java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonJVMOptions) {
		t.Fatalf("_JAVA_OPTIONS not flagged: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("plain heap option should stay a warning: %s", audit.Describe())
	}
}

func TestEnvJDKJavaOptionsAgent(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "JDK_JAVA_OPTIONS='-agentlib:jdwp=server=y'\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonJVMAgent) {
		t.Fatalf("agentlib not flagged: %s", audit.Describe())
	}
}

func TestEnvBashEnvBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "export BASH_ENV=/tmp/hook.sh\nexec java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonShellInit) {
		t.Fatalf("BASH_ENV not flagged: %s", audit.Describe())
	}
}

func TestEnvNodeOptionsWarning(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "run.sh", "export NODE_OPTIONS=--inspect=0.0.0.0:9229\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonToolInject) {
		t.Fatalf("NODE_OPTIONS not flagged: %s", audit.Describe())
	}
}

func TestEnvPathDotBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "export PATH=.:$PATH\nexec java -jar server.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !audit.Blocking() || !envHasReason(audit, envReasonPathHijack) {
		t.Fatalf("PATH . must block: %s", audit.Describe())
	}
}

func TestEnvPathTmpBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.bat", "SET PATH=%TEMP%;%PATH%\r\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonPathHijack) {
		t.Fatalf("PATH temp not flagged: %s", audit.Describe())
	}
}

func TestEnvPythonPathWarning(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "env.sh", "export PYTHONPATH=/tmp/site-packages\n")
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonPythonHook) || audit.Blocking() {
		t.Fatalf("PYTHONPATH should warn only: %s", audit.Describe())
	}
}

func TestEnvCommentsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", "# export LD_PRELOAD=/tmp/x.so\n:: SET CLASSPATH=evil.jar\n")
	audit := AuditServerEnvironmentHijack(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("comments must be ignored: %s", audit.Describe())
	}
}

func TestEnvSymlinkedScriptBlocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sh")
	writeACFile(t, dir, "real.sh", "java -jar server.jar\n")
	link := filepath.Join(dir, "start.sh")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerEnvironmentHijack(dir)
	if !audit.Blocking() || !envHasReason(audit, envReasonSymlink) {
		t.Fatalf("symlinked script must block: %s", audit.Describe())
	}
}

func TestEnvOversizedScriptBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "start.sh", strings.Repeat("a", envMaxFileBytes+1))
	audit := AuditServerEnvironmentHijack(dir)
	if !envHasReason(audit, envReasonTooLarge) || !audit.Blocking() {
		t.Fatalf("oversized script must block: %s", audit.Describe())
	}
}

func TestEnvSummaryAndCodes(t *testing.T) {
	audit := EnvHijackAudit{Dir: "x"}
	audit.add("start.sh", "LD_PRELOAD", envReasonPreload, "preload", true)
	audit.add("start.sh", "PYTHONPATH", envReasonPythonHook, "hook", false)
	codes := audit.Codes()
	if len(codes) != 2 || codes[0] != envReasonPreload {
		t.Fatalf("codes not sorted: %v", codes)
	}
	if !strings.Contains(audit.Summary(), "blocking=1") || !strings.Contains(audit.Summary(), "warnings=1") {
		t.Fatalf("summary wrong: %s", audit.Summary())
	}
}
