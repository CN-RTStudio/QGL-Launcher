package main

// maxInt63 返回 math.MaxInt64，单独包一层避免在本文件再 import math。
func maxInt63() int64 { return 1<<63 - 1 }

// planDownloadDiskFit 对每个目录的已知需求做磁盘裁决。
// probe 一般传 probeDownloadDiskFit(path, requested, inflight)；测试可注入桩。
// 每个目录把本目录全部已知需求作为 requested、inflight=0 传入（因为按目录聚合后，
// 该目录所有 pending 字节就是本次将要写入的总量，requested+inflight 恒等于总需求）。
func planDownloadDiskFit(demands []diskDirDemand, probe func(path string, requested, inflight int64) DiskFitAssessment) []diskDirPlan {
	plans := make([]diskDirPlan, 0, len(demands))
	for i := range demands {
		d := demands[i]
		var assess DiskFitAssessment
		if probe == nil {
			assess = assessDiskFit(diskAvailUnknown, d.KnownBytes, 0)
		} else {
			assess = probe(d.Path, d.KnownBytes, 0)
		}
		plans = append(plans, diskDirPlan{Demand: d, Assessment: assess})
	}
	return plans
}

// blockingDiskPlans 返回会阻止下载开始的目录计划（short 或 bad-input）。
// unknown / ok 都不阻止：探测失败不误杀，空间充足放行。
func blockingDiskPlans(plans []diskDirPlan) []diskDirPlan {
	var blocked []diskDirPlan
	for i := range plans {
		v := plans[i].Assessment.Verdict
		if v == diskFitShort || v == diskFitBadInput {
			blocked = append(blocked, plans[i])
		}
	}
	return blocked
}

// describeDiskPlanBlock 汇总一个阻止计划的人类可读说明。
func describeDiskPlanBlock(p diskDirPlan) string {
	base := describeDiskFit(p.Assessment)
	if base == "" {
		return ""
	}
	return "下载目录 " + p.Demand.Path + "：" + base
}
