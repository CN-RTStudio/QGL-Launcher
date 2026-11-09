package main

// jvmmitigations_test.go —— 强制 JVM 缓解属性内核的表驱动测试。

import "testing"

func TestEnforcedJvmPropertyKeysContainsExpected(t *testing.T) {
	want := []string{
		"log4j2.formatmsgnolookups",
		"com.sun.jndi.ldap.object.trusturlcodebase",
		"com.sun.jndi.rmi.object.trusturlcodebase",
		"com.sun.jndi.cosnaming.object.trusturlcodebase",
	}
	for _, k := range want {
		if !isEnforcedJvmProperty(k) {
			t.Fatalf("强制键缺失: %s", k)
		}
	}
	if isEnforcedJvmProperty("log4j2.configurationfile") {
		t.Fatal("普通 log4j 属性不应被判为强制键")
	}
	if isEnforcedJvmProperty("") {
		t.Fatal("空属性名不应命中")
	}
}

func TestEnforcedJvmPropertyArgsShape(t *testing.T) {
	args := enforcedJvmPropertyArgs()
	if len(args) != 4 {
		t.Fatalf("期望 4 条强制属性，得到 %d: %v", len(args), args)
	}
	last := args[len(args)-1]
	if last != "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false" {
		t.Fatalf("末条强制属性不符: %s", last)
	}
	first := args[0]
	if first != "-Dlog4j2.formatMsgNoLookups=true" {
		t.Fatalf("首条强制属性应保持规范大小写: %s", first)
	}
}

func TestApplyEnforcedJvmProperties(t *testing.T) {
	// 每条用例验证“外部/启动器参数 → 收敛后参数”。
	cases := []struct {
		name string
		in   []string
		// 只校验关键不变量：强制键出现次数、最终末尾是否为强制段、普通参数是否保留。
		wantTail         string // 收敛后最后一个元素
		wantCountLog4j   int    // 收敛后含 log4j2.formatMsgNoLookups（任意大小写）的条数
		wantCountLdap    int
		wantKeepOrdinary bool   // -Xmx2G 是否保留
		wantLen          int    // 0 表示不校验长度
	}{
		{
			name:             "空输入也补齐四条强制属性",
			in:               nil,
			wantTail:         "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false",
			wantCountLog4j:   1,
			wantCountLdap:    1,
			wantKeepOrdinary: false,
			wantLen:          4,
		},
		{
			name: "前置 true 被规范化为末尾单份，不重复",
			in: []string{
				"-Xmx2G",
				"-Dlog4j2.formatMsgNoLookups=true",
			},
			wantTail:         "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false",
			wantCountLog4j:   1,
			wantCountLdap:    1,
			wantKeepOrdinary: true,
		},
		{
			name: "不可信 JSON 后置 false 撤销被驳回，末尾仍 true",
			in: []string{
				"-Xmx2G",
				"-Dlog4j2.formatMsgNoLookups=true",
				"-DLOG4J2.FORMATMSGNLOOKUPS=FALSE", // 模拟恶意版本 JSON 覆盖
			},
			wantTail:         "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false",
			wantCountLog4j:   1,
			wantCountLdap:    1,
			wantKeepOrdinary: true,
		},
		{
			name: "无值形式与混合大小写的强制键同样被剔除",
			in: []string{
				"-DLog4j2.FormatMsgNoLookups",
				"-DCOM.SUN.JNDI.LDAP.OBJECT.TRUSTURLCODEBASE=true",
			},
			wantTail:       "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false",
			wantCountLog4j: 1,
			wantCountLdap:  1, // 恶意 true 被剔除，仅末尾规范 false
		},
		{
			name: "ldap/rmi/cosnaming 全部强制为 false 且各仅一份",
			in: []string{
				"-Dcom.sun.jndi.rmi.object.trustURLCodebase=true",
				"-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=true",
			},
			wantTail:       "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false",
			wantCountLog4j: 1,
			wantCountLdap:  1,
		},
		{
			name: "普通 -D 与 -XX 参数原样保留",
			in: []string{
				"-Xmx2G",
				"-XX:+UseG1GC",
				"-Djava.library.path=C:\\natives",
				"-Dfabric.someProp=abc",
			},
			wantTail:         "-Dcom.sun.jndi.cosnaming.object.trustURLCodebase=false",
			wantCountLog4j:   1,
			wantCountLdap:    1,
			wantKeepOrdinary: true,
			wantLen:          8, // 4 普通 + 4 强制
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := applyEnforcedJvmProperties(tc.in)
			if len(out) == 0 {
				t.Fatal("收敛结果为空")
			}
			if out[len(out)-1] != tc.wantTail {
				t.Fatalf("末尾强制属性不符:\n got=%s\nwant=%s\nall=%v",
					out[len(out)-1], tc.wantTail, out)
			}
			nLog4j, nLdap := 0, 0
			keepXmx := false
			for _, a := range out {
				low := lowerAscii(a)
				if hasPrefix(low, "-dlog4j2.formatmsgnolookups") {
					nLog4j++
					// 唯一保留的那份必须是强制 true。
					if a != "-Dlog4j2.formatMsgNoLookups=true" {
						t.Fatalf("出现非规范 log4j 强制项: %s (%v)", a, out)
					}
				}
				if hasPrefix(low, "-dcom.sun.jndi.ldap.object.trusturlcodebase") {
					nLdap++
					if a != "-Dcom.sun.jndi.ldap.object.trustURLCodebase=false" {
						t.Fatalf("出现非规范 ldap 强制项: %s (%v)", a, out)
					}
				}
				if a == "-Xmx2G" {
					keepXmx = true
				}
			}
			if nLog4j != tc.wantCountLog4j {
				t.Fatalf("log4j 强制项条数=%d 期望 %d (%v)", nLog4j, tc.wantCountLog4j, out)
			}
			if nLdap != tc.wantCountLdap {
				t.Fatalf("ldap 强制项条数=%d 期望 %d (%v)", nLdap, tc.wantCountLdap, out)
			}
			if keepXmx != tc.wantKeepOrdinary {
				t.Fatalf("-Xmx2G 保留情况=%v 期望 %v (%v)", keepXmx, tc.wantKeepOrdinary, out)
			}
			if tc.wantLen != 0 && len(out) != tc.wantLen {
				t.Fatalf("长度=%d 期望 %d (%v)", len(out), tc.wantLen, out)
			}
			// 强制段必须整体位于末尾 4 位。
			tail := out[len(out)-4:]
			wantTail := enforcedJvmPropertyArgs()
			for i := range wantTail {
				if tail[i] != wantTail[i] {
					t.Fatalf("强制段未位于末尾:\n got=%v\nwant=%v", tail, wantTail)
				}
			}
		})
	}
}

func TestApplyEnforcedDoesNotMutateInput(t *testing.T) {
	in := []string{"-Xmx2G", "-Dlog4j2.formatMsgNoLookups=false"}
	inCopy := append([]string(nil), in...)
	_ = applyEnforcedJvmProperties(in)
	for i := range in {
		if in[i] != inCopy[i] {
			t.Fatalf("入参被修改: %v -> %v", inCopy, in)
		}
	}
}

// hasPrefix 是 strings.HasPrefix 的本地最小实现，避免为测试引入额外 import 风格分歧。
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
