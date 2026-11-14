package main

func bombFail(code string) error { return &bombErr{code: code} }

// EntryInput 是调用方提供的一条压缩包条目客观信息。
type EntryInput struct {
	Name         string
	IsDir        bool
	Compressed   int64 // 该条目压缩后字节数；不可知时给 0
	Uncompressed int64 // 该条目声称/实得的解压字节数
	Zip64        bool  // 该条目是否使用 zip64 扩展尺寸
}

// ArchiveBombAuditor 是单次解压过程的有状态审计器。
type ArchiveBombAuditor struct {
	policy       ArchiveBombPolicy
	entries      int
	totalUncomp  int64
	totalComp    int64
	seenNames    map[string]struct{}
	largestRatio float64
}

// NewArchiveBombAuditor 按策略构造审计器；策略非法直接报错，防止“零值全放开”。
func NewArchiveBombAuditor(policy ArchiveBombPolicy) (*ArchiveBombAuditor, error) {
	if policy.MaxUncompressedTotal <= 0 || policy.MaxSingleEntry <= 0 ||
		policy.MaxEntries <= 0 || policy.MaxNameLen <= 0 || policy.MaxNestDepth < 0 {
		return nil, bombFail(BombReasonPolicy)
	}
	return &ArchiveBombAuditor{
		policy:    policy,
		seenNames: make(map[string]struct{}),
	}, nil
}

// AddEntry 在解压某个条目前调用。返回的错误实现 BombError，可断言原因码。

func (a *ArchiveBombAuditor) AddEntry(in EntryInput) error {
	if in.Compressed < 0 || in.Uncompressed < 0 {
		return bombFail(BombReasonNegativeSize)
	}
	if len(in.Name) > a.policy.MaxNameLen {
		return bombFail(BombReasonNameTooLong)
	}
	if a.entries >= a.policy.MaxEntries {
		return bombFail(BombReasonTooManyEntries)
	}
	if in.Zip64 && !a.policy.AllowZip64 {
		return bombFail(BombReasonZip64Denied)
	}
	// 重复名字（区分大小写按归档原样比较）：可能用于覆盖混淆。
	if _, dup := a.seenNames[in.Name]; dup {
		return bombFail(BombReasonDuplicateName)
	}
	if in.Uncompressed > a.policy.MaxSingleEntry {
		return bombFail(BombReasonEntryTooLarge)
	}
	if a.totalUncomp+in.Uncompressed > a.policy.MaxUncompressedTotal {
		return bombFail(BombReasonTotalTooLarge)
	}

	// 压缩比按“当前累计 + 本条目”滚动计算，避免单条小压缩大解压钻空子。
	// 目录条目不参与比值（压缩字节常记 0）。
	if !in.IsDir && a.policy.MaxCompressionRatio > 0 {
		comp := a.totalComp + in.Compressed
		uncomp := a.totalUncomp + in.Uncompressed
		if comp > 0 {
			r := float64(uncomp) / float64(comp)
			if r > a.largestRatio {
				a.largestRatio = r
			}
			if r > a.policy.MaxCompressionRatio {
				return bombFail(BombReasonRatio)
			}
		}
	}

	a.seenNames[in.Name] = struct{}{}
	a.entries++
	a.totalUncomp += in.Uncompressed
	a.totalComp += in.Compressed
	return nil
}
