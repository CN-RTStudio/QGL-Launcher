package main

import (
	"fmt"
)

const (
	scbMaxFindings      = 48
	scbMaxProps         = 256 * 1024
	scbMaxYAML          = 512 * 1024
	scbDefaultChainMax  = 65536
	scbHardChainMax     = 262144
	scbDefaultForkMax   = 256
	scbHardForkMax      = 1024
	scbReasonOK         = "ok"
	scbReasonMissing    = "missing"
	scbReasonSymlink    = "symlink"
	scbReasonTooLarge   = "too-large"
	scbReasonUnreadable = "unreadable"
	scbReasonBadValue   = "bad-value"
	scbReasonChainLong  = "command-chain-too-long"
	scbReasonForkHigh   = "command-fork-too-high"
	scbReasonOpHigh     = "op-level-maximum"
	scbReasonFnHigh     = "function-level-maximum"
	scbReasonRCECombo   = "command-block-rce-surface"
	scbReasonSilent     = "silent-commandblock-console"
	scbReasonNoBlock    = "command-block-disabled"
	scbReasonSpamList   = "spam-exclusion-widened"
)

type CommandBlockFinding = auditFinding

type CommandBlockAudit struct {
	ServerDir string
	Findings  []CommandBlockFinding
}

func scbCheckProperties(a *CommandBlockAudit, props map[string]string) {
	enabled, known := scbPropBool(props, "enable-command-block")
	if !known {
		a.add("server.properties", scbReasonNoBlock, "缺少 enable-command-block 声明，按默认禁用处理", false)
	} else if !enabled {
		a.add("server.properties", scbReasonNoBlock, "enable-command-block=false，命令方块全部禁用", false)
	}

	chain, chainKnown := scbPropInt(props, "maxCommandChainLength")
	if chainKnown {
		switch {
		case chain <= 0:
			a.add("server.properties", scbReasonChainLong, "maxCommandChainLength 非正数，命令链无上限", true)
		case chain > scbHardChainMax:
			a.add("server.properties", scbReasonChainLong, fmt.Sprintf("maxCommandChainLength=%d 超过硬上限 %d", chain, scbHardChainMax), true)
		case chain > scbDefaultChainMax:
			a.add("server.properties", scbReasonChainLong, fmt.Sprintf("maxCommandChainLength=%d 高于默认 %d", chain, scbDefaultChainMax), false)
		}
	}

	fork, forkKnown := scbPropInt(props, "maxCommandForkCount")
	if forkKnown {
		switch {
		case fork <= 0:
			a.add("server.properties", scbReasonForkHigh, "maxCommandForkCount 非正数，命令分叉不受限", true)
		case fork > scbHardForkMax:
			a.add("server.properties", scbReasonForkHigh, fmt.Sprintf("maxCommandForkCount=%d 超过硬上限 %d", fork, scbHardForkMax), true)
		case fork > scbDefaultForkMax:
			a.add("server.properties", scbReasonForkHigh, fmt.Sprintf("maxCommandForkCount=%d 高于默认 %d", fork, scbDefaultForkMax), false)
		}
	}

	opLevel, opKnown := scbPropInt(props, "op-permission-level")
	if opKnown {
		switch {
		case opLevel < 1 || opLevel > 4:
			a.add("server.properties", scbReasonBadValue, fmt.Sprintf("op-permission-level=%d 超出 1..4", opLevel), false)
		case opLevel >= 4:
			a.add("server.properties", scbReasonOpHigh, "op-permission-level=4，管理员可执行全部命令", false)
		}
	}

	fnLevel, fnKnown := scbPropInt(props, "function-permission-level")
	if fnKnown {
		switch {
		case fnLevel < 1 || fnLevel > 4:
			a.add("server.properties", scbReasonBadValue, fmt.Sprintf("function-permission-level=%d 超出 1..4", fnLevel), false)
		case fnLevel >= 4:
			a.add("server.properties", scbReasonFnHigh, "function-permission-level=4，函数以最高权限执行", false)
		}
	}

	if known && enabled && fnKnown && fnLevel >= 4 {
		a.add("server.properties", scbReasonRCECombo, "命令方块启用且函数权限为 4，数据包函数可直接执行高权限命令", true)
	}
	if known && enabled && opKnown && opLevel >= 4 {
		a.add("server.properties", scbReasonRCECombo, "命令方块启用且 op 权限为 4，命令方块可执行高权限命令", true)
	}
}
