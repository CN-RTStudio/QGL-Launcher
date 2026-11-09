package main

func buildModAuditReportFile(r ModAuditReport, baseline *ModAuditSnapshot, now string) ModAuditReportFile {
	sortReportDeltas(r.Added)
	sortReportDeltas(r.Missing)
	sortReportDeltas(r.Tampered)
	added, addedRest := clipReportDeltas(r.Added, modAuditReportMaxRows)
	missing, missingRest := clipReportDeltas(r.Missing, modAuditReportMaxRows)
	tampered, tamperedRest := clipReportDeltas(r.Tampered, modAuditReportMaxRows)
	for i := range added {
		added[i].Detail = clipDetail(added[i].Detail)
	}
	for i := range missing {
		missing[i].Detail = clipDetail(missing[i].Detail)
	}
	for i := range tampered {
		tampered[i].Detail = clipDetail(tampered[i].Detail)
	}
	out := ModAuditReportFile{
		Version:       modAuditBaselineVersion,
		GeneratedAt:   now,
		Total:         r.Total,
		Consistent:    r.Consistent,
		Skipped:       r.Skipped,
		LimitHit:      r.LimitHit,
		HasRisks:      r.HasRisks,
		Added:         added,
		Missing:       missing,
		Tampered:      tampered,
		AddedCount:    len(r.Added),
		MissingCount:  len(r.Missing),
		TamperedCount: len(r.Tampered),
	}
	if baseline != nil {
		out.BaselineAt = baseline.CreatedAt
		out.BaselineDirs = len(baseline.Dirs)
	}
	_ = addedRest
	_ = missingRest
	_ = tamperedRest
	return out
}
