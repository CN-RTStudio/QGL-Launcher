package main

import (
	"crypto/subtle"
	"encoding/hex"
	"time"
)

func VerifyLaunchPIN(store lockStore, pin string, lim LockLimits) (bool, string, int) {
	if lim.MinPINLen == 0 {
		lim = defaultLockLimits()
	}
	if len(pin) < lim.MinPINLen || len(pin) > lim.MaxPINLen {
		return false, "pin-length-out-of-range", -1
	}
	raw, err := store.Load()
	if err != nil || len(raw) == 0 {
		return false, "pin-unset", -1
	}
	st := normalizeLockState(raw)
	now := time.Now().UnixNano()
	if st.LockedUntil > now {
		return false, "pin-locked", 0
	}
	salt, err := hex.DecodeString(st.SaltHex)
	if err != nil {
		return false, "pin-corrupt", -1
	}
	sum := umfsLockDigest([]byte(pin), salt)
	expected, err := hex.DecodeString(st.HMACHex)
	if err != nil {
		return false, "pin-corrupt", -1
	}
	if subtle.ConstantTimeCompare(sum, expected) == 1 {
		st.Fails = 0
		st.LastVerified = now
		payload, _ := st.marshal()
		_ = store.Save(payload)
		return true, "", lim.MaxAttempt
	}
	st.Fails++
	remaining := lim.MaxAttempt - st.Fails
	if remaining <= 0 {
		st.Fails = 0
		st.LockedUntil = now + lim.Cooldown.Nanoseconds()
		remaining = 0
	}
	payload, _ := st.marshal()
	_ = store.Save(payload)
	return false, "pin-wrong", remaining
}

func ClearLaunchPIN(store lockStore, pin string, lim LockLimits) error {
	ok, _, _ := VerifyLaunchPIN(store, pin, lim)
	if !ok {
		return errText("pin-verify-fail")
	}
	if err := store.Save(nil); err != nil {
		return errText("pin-clear-store")
	}
	return nil
}
func LockStatus(store lockStore, lim LockLimits) (configured bool, remaining int, locked bool, untilUnixNano int64) {
	if lim.MinPINLen == 0 {
		lim = defaultLockLimits()
	}
	raw, err := store.Load()
	if err != nil || len(raw) == 0 {
		return false, lim.MaxAttempt, false, 0
	}
	st := normalizeLockState(raw)
	now := time.Now().UnixNano()
	if st.LockedUntil > now {
		return true, 0, true, st.LockedUntil
	}
	return true, lim.MaxAttempt - st.Fails, false, 0
}
func SummarizeLockStatus(configured bool, remaining int, locked bool) string {
	if !configured {
		return "launch-lock unset"
	}
	if locked {
		return "launch-lock locked"
	}
	return "launch-lock armed remaining=" + itoaSafe(remaining)
}
