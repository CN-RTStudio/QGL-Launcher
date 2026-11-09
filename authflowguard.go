package main

// AuthFlowLimits 限定 OAuth 流程各输入的长度与有效期边界。
type AuthFlowLimits struct {
	MaxStateRunes    int
	MaxTokenRunes    int
	MaxCodeRunes     int
	TokenLifetimeSec int64
}

func (l *AuthFlowLimits) withDefaults() AuthFlowLimits {
	if l == nil {
		l = &AuthFlowLimits{}
	}
	out := *l
	if out.MaxStateRunes <= 0 {
		out.MaxStateRunes = 128
	}
	if out.MaxTokenRunes <= 0 {
		out.MaxTokenRunes = 4096
	}
	if out.MaxCodeRunes <= 0 {
		out.MaxCodeRunes = 512
	}
	if out.TokenLifetimeSec <= 0 {
		out.TokenLifetimeSec = 86400
	}
	return out
}

// AuthVerdict 是 OAuth 校验的结构化结论。
type AuthVerdict struct {
	Ok      bool
	Reasons []string // 未通过的理由，可多条
}

func (v *AuthVerdict) fail(reason string) {
	v.Ok = false
	v.Reasons = append(v.Reasons, reason)
}
