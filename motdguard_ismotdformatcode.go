package main

import ()

func isMOTDFormatCode(code rune) bool {
	if (code >= '0' && code <= '9') || (code >= 'a' && code <= 'f') {
		return true
	}
	switch code {
	case 'k', 'l', 'm', 'n', 'o', 'r':
		return true
	}
	return false
}

// stripTerminalSequences 整段剥除终端转义序列，而非只删 ESC 单字节：
//
//	CSI：ESC '[' 参数(0x20-0x3f)* 终止(0x40-0x7e)；C1 形态 0x9b 同 CSI
//	OSC：ESC ']' … 直到 BEL(0x07) 或 ST(ESC '\')，或字符串结束
//	其余紧跟 ESC 的形式（ESC c 复位、ESC ( 选择字符集）视作单 ESC 丢弃。
