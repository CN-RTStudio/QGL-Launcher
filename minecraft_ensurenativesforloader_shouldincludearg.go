package main

import (

)

func shouldIncludeArg(arg map[string]interface{}) bool {
	rulesRaw, ok := arg["rules"]
	if !ok {
		// 没有 rules，默认包含
		return true
	}

	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return true
	}

	// 遍历所有规则
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		action, _ := rule["action"].(string)
		if action == "" {
			continue
		}

		// 检查 features 规则（参考PCL：is_demo_user 的规则应该排除）
		if features, hasFeatures := rule["features"]; hasFeatures {
			if featMap, ok := features.(map[string]interface{}); ok {
				// 如果规则包含 is_demo_user，则排除此参数（我们不是 demo 用户）
				if _, isDemo := featMap["is_demo_user"]; isDemo {
					return false
				}
			}
		}

		// 检查 os 规则
		osRule, hasOS := rule["os"].(map[string]interface{})
		matchesOS := true
		if hasOS {
			osName, _ := osRule["name"].(string)
			// 我们在 Windows 上运行
			matchesOS = osName == "windows"
		}

		if action == "allow" {
			// allow 规则：如果匹配则允许
			if !matchesOS {
				return false
			}
		} else if action == "disallow" {
			// disallow 规则：如果匹配则禁止
			if matchesOS {
				return false
			}
		}
	}

	return true
}

// fixForgeModuleConflict 修复 Forge 启动时的 Java 模块系统冲突
// 问题：Forge 版本 JSON 的 arguments.jvm 中包含 --add-modules ALL-MODULE-PATH
// 这会让 Java 自动加载 classpath 中所有带 module-info.class 的 JAR 作为模块
// minecraft.jar (模块名 minecraft) 和 Forge JAR (模块名 _1._19._2 等) 都导出 net.minecraft.server → ResolutionException
// 解决方案：添加 --limit-modules 限制只加载 BootstrapLauncher 需要的核心模块，
//          排除 minecraft 和 Forge 内部模块，避免冲突
