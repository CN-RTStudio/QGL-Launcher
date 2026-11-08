package main

import (
	"testing"
)

func TestFindModClassConflicts_Basic(t *testing.T) {
	mods := []ModClassEntry{
		{ModName: "A", ClassKey: "net/minecraft/client/gui/GuiScreen"},
		{ModName: "B", ClassKey: "net/minecraft/client/gui/GuiScreen"},
		{ModName: "C", ClassKey: "net/minecraft/client/Particle"},
	}
	got := FindModClassConflicts(mods)
	if len(got) != 1 {
		t.Fatalf("expected 1 conflict group, got %v", got)
	}
	if got[0][0] != "A" || got[0][1] != "B" {
		t.Fatalf("expected [A B], got %v", got[0])
	}
}

func TestFindModClassConflicts_DedupSameMod(t *testing.T) {
	mods := []ModClassEntry{
		{ModName: "A", ClassKey: "X"},
		{ModName: "A", ClassKey: "X"},
	}
	got := FindModClassConflicts(mods)
	if len(got) != 0 {
		t.Fatalf("same mod twice must not conflict, got %v", got)
	}
}

func TestFindModClassConflicts_EmptyClassKeySkipped(t *testing.T) {
	mods := []ModClassEntry{
		{ModName: "A", ClassKey: "  "},
		{ModName: "B", ClassKey: ""},
	}
	got := FindModClassConflicts(mods)
	if len(got) != 0 {
		t.Fatalf("empty keys must be ignored, got %v", got)
	}
}

func TestIsKnownAntipair(t *testing.T) {
	if !IsKnownAntipair("OptiFine_1.20", "Sodium-fabric") {
		t.Fatal("optifine+sodium must be antipair")
	}
	if IsKnownAntipair("JEI", "Hwyla") {
		t.Fatal("jei+hwyla is fine")
	}
	if !IsKnownAntipair("iris", "OptiFine") {
		t.Fatal("iris+optifine must be antipair (reversed)")
	}
}
