package main

import "testing"

func TestLoaderSwitch_SameOK(t *testing.T) {
	w := WorldLoaderReport{WorldName: "w", Loader: LoaderFabric, ModCount: 5}
	if AssessLoaderSwitch(w, LoaderFabric) != RiskOK {
		t.Fatal("same loader must be OK")
	}
}

func TestLoaderSwitch_VanillaToFabricNoMods(t *testing.T) {
	w := WorldLoaderReport{Loader: LoaderVanilla, ModCount: 0}
	if AssessLoaderSwitch(w, LoaderFabric) != RiskWarning {
		t.Fatal("vanilla empty world to fabric should be warning")
	}
}

func TestLoaderSwitch_VanillaToFabricWithMods(t *testing.T) {
	w := WorldLoaderReport{Loader: LoaderVanilla, ModCount: 3}
	if AssessLoaderSwitch(w, LoaderFabric) != RiskDanger {
		t.Fatal("vanilla world with mods to fabric should be danger")
	}
}

func TestLoaderSwitch_ForgeToNeoForgeWarning(t *testing.T) {
	w := WorldLoaderReport{Loader: LoaderForge, ModCount: 10}
	if AssessLoaderSwitch(w, LoaderNeoForge) != RiskWarning {
		t.Fatal("forge->neoforge should be warning")
	}
}

func TestLoaderSwitch_FabricToQuiltWarning(t *testing.T) {
	w := WorldLoaderReport{Loader: LoaderFabric, ModCount: 10}
	if AssessLoaderSwitch(w, LoaderQuilt) != RiskWarning {
		t.Fatal("fabric->quilt should be warning")
	}
}

func TestLoaderSwitch_ForgeToFabricDanger(t *testing.T) {
	w := WorldLoaderReport{Loader: LoaderForge, ModCount: 10}
	if AssessLoaderSwitch(w, LoaderFabric) != RiskDanger {
		t.Fatal("forge->fabric must be danger")
	}
}

func TestRiskLabel(t *testing.T) {
	if RiskOK.RiskLabel() != "ok" || RiskDanger.RiskLabel() != "danger" {
		t.Fatal("labels wrong")
	}
}
