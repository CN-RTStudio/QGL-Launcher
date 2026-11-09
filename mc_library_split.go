package main

func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent
	if child.ID != "" {
		merged.ID = child.ID
	}
	if child.MainClass != "" {
		merged.MainClass = child.MainClass
	}
	if child.Type != "" {
		merged.Type = child.Type
	}
	if child.ReleaseTime != "" {
		merged.ReleaseTime = child.ReleaseTime
	}
	if child.Jar != "" {
		merged.Jar = child.Jar
	}
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		childGroupArtifacts[libGroupArtifact(lib.Name)] = true
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		if !childGroupArtifacts[libGroupArtifact(lib.Name)] {
			mergedLibs = append(mergedLibs, lib)
		}
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}
	merged.InheritsFrom = child.InheritsFrom
	return merged
}
