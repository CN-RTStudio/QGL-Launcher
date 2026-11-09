package main

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
