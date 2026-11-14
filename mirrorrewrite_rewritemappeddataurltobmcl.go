package main

func rewriteMappedDataURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMappedDataPrefixRules)
}

var bmclMavenLibPrefixRules = []urlPrefixRule{
	{"https://maven.minecraftforge.net/", bmclMirrorBase + "/maven/"},
	{"https://maven.neoforged.net/releases/", bmclMirrorBase + "/maven/"},
	{"https://maven.fabricmc.net/", bmclMirrorBase + "/maven/"},
}

func rewriteMavenLibURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMavenLibPrefixRules)
}

var bmclFabricLibPrefixRules = []urlPrefixRule{
	{"https://maven.fabricmc.net/", bmclMirrorBase + "/maven/"},
	{"https://repo1.maven.org/maven2/", bmclMirrorBase + "/maven/"},
	{"https://libraries.minecraft.net/", bmclMirrorBase + "/libraries/"},
}

func rewriteFabricLibURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclFabricLibPrefixRules)
}

var bmclMavenCentralPrefixRules = []urlPrefixRule{
	{"https://repo1.maven.org/maven2/", bmclMirrorBase + "/maven/"},
}

func rewriteMavenCentralURLToBMCL(raw string) string {
	return rewriteURLPrefixes(raw, bmclMavenCentralPrefixRules)
}

var bmclLibraryArtifactPrefixRules = []urlPrefixRule{
	{"https://libraries.minecraft.net/", bmclMirrorBase + "/libraries/"},
}
