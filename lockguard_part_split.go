package main

import "time"

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
