package main

import (
	"testing"
)

func TestFilterUntrustedJvmArgsBlocksCodeExecFlags(t *testing.T) {
	in := []string{
		"-javaagent:evil.jar",
		"-XX:OnError=calc.exe",
		"-XX:OnOutOfMemoryError=cmd /c calc",
		"-agentlib:jdwp=transport=dt_socket,server=y,address=*:5005",
		"-agentpath:C:\\evil.dll",
		"-XX:VMOptionsFile=C:\\opts.txt",
		"-XXaltjvm=D:\\fakejvm",
		"-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005",
	}
	safe, blocked, truncated := filterUntrustedJvmArgs(in)
	if len(safe) != 0 {
		t.Fatalf("expected no safe args, got %v", safe)
	}
	if len(blocked) != len(in) {
		t.Fatalf("expected %d blocked flags, got %d: %v", len(in), len(blocked), blocked)
	}
	if truncated {
		t.Fatal("truncated should be false for small list")
	}
}

func TestFilterUntrustedJvmArgsKeepsOfficialFlags(t *testing.T) {
	in := []string{
		"-Djava.library.path=C:\\mc\\natives",
		"-Dorg.lwjgl.librarypath=C:\\mc\\natives",
		"-cp", "lib1.jar;lib2.jar",
		"--add-opens", "java.base/java.lang=ALL-UNNAMED",
		"--add-exports", "java.base/sun.nio.ch=ALL-UNNAMED",
		"--add-modules", "jdk.crypto.cryptoki",
		"--enable-native-access=ALL-UNNAMED",
		"-p", "C:\\mc\\libraries",
		"--module-path=C:\\mc\\libraries",
		"-Xmx4G", "-Xms1G", "-Xss2M",
		"-XX:+UseG1GC", "-XX:G1HeapRegionSize=32M",
		"-Dfabric.loader.game.version=1.21",
	}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(blocked) != 0 {
		t.Fatalf("official flags must not be blocked: %v", blocked)
	}
	if len(safe) != len(in) {
		t.Fatalf("expected all %d args kept, got %d: %v", len(in), len(safe), safe)
	}
}

func TestFilterUntrustedJvmArgsDropsSeparateOperand(t *testing.T) {
	// "-jar evil.jar"、"-m module/main" 的操作数是独立 token，必须一并丢弃，
	// 否则操作数会被当成一个孤立的 JVM 参数传给 java。
	in := []string{"-Dok=1", "-jar", "evil.jar", "-Xmx2G", "-m", "evil/evil.Main", "-Dtail=1"}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(blocked) != 2 || blocked[0] != "-jar" || blocked[1] != "-m" {
		t.Fatalf("unexpected blocked list: %v", blocked)
	}
	want := []string{"-Dok=1", "-Xmx2G", "-Dtail=1"}
	if len(safe) != len(want) {
		t.Fatalf("expected %v, got %v", want, safe)
	}
	for i := range want {
		if safe[i] != want[i] {
			t.Fatalf("safe[%d]=%q, want %q", i, safe[i], want[i])
		}
	}
}

func TestFilterUntrustedJvmArgsCaseInsensitive(t *testing.T) {
	in := []string{"-JAVAAGENT:Evil.JAR", "-xx:onerror=calc", "-XrUnJdWP:x"}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(safe) != 0 || len(blocked) != 3 {
		t.Fatalf("case-insensitive match failed: safe=%v blocked=%v", safe, blocked)
	}
}

func TestFilterUntrustedJvmArgsTruncates(t *testing.T) {
	in := make([]string, 0, maxUntrustedJvmArgs+10)
	for i := 0; i < maxUntrustedJvmArgs+10; i++ {
		in = append(in, "-Dbenchmark.prop=value")
	}
	safe, _, truncated := filterUntrustedJvmArgs(in)
	if !truncated {
		t.Fatal("expected truncated=true when exceeding maxUntrustedJvmArgs")
	}
	if len(safe) != maxUntrustedJvmArgs {
		t.Fatalf("expected exactly %d kept, got %d", maxUntrustedJvmArgs, len(safe))
	}
}

func TestIsDangerousJvmFlagBoundaries(t *testing.T) {
	bad := []string{
		"-javaagent", "-javaagent:a.jar", "-JAVAAGENT:x",
		"-xx:onerror", "-xx:onerror=cmd",
		"-jar", "-m", "--module", "-xrunjdwp:x",
	}
	for _, b := range bad {
		if !isDangerousJvmFlag(b) {
			t.Errorf("expected dangerous: %q", b)
		}
	}
	good := []string{"-xmx2g", "-xx:+useg1gc", "-djava.library.path=x", "-xss1m", "--module-path=x"}
	for _, g := range good {
		if isDangerousJvmFlag(g) {
			t.Errorf("expected safe: %q", g)
		}
	}
}

func TestJvmArgThreatBlocksArgumentFiles(t *testing.T) {
	bad := []string{
		"@C:\\Users\\victim\\evil.txt",
		"@opts",
		"@./rel/args",
		"@", // 裸 @ 也拒绝，fail-closed
	}
	for _, b := range bad {
		dangerous, consumes := jvmArgThreat(b)
		if !dangerous {
			t.Errorf("argument file must be dangerous: %q", b)
		}
		if consumes {
			t.Errorf("@argfile 不应吞掉下一 token（路径在同一参数内）: %q", b)
		}
	}
}
