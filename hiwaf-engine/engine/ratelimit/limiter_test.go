package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecordBansAfterLimit(t *testing.T) {
	s := NewState()
	now := time.Unix(1000, 0)
	lim := Limit{Requests: 3, WindowSec: 10, BanSec: 60}
	for i := 0; i < 3; i++ {
		_, b := s.Record(KindAccess, "1.1.1.1", lim, now)
		assert.False(t, b)
	}
	until, b := s.Record(KindAccess, "1.1.1.1", lim, now)
	assert.True(t, b)
	assert.Equal(t, now.Add(60*time.Second), until)
	_, banned := s.BannedUntil("1.1.1.1", now.Add(59*time.Second))
	assert.True(t, banned)
	_, banned = s.BannedUntil("1.1.1.1", now.Add(61*time.Second))
	assert.False(t, banned)

	// Already banned: not counted, not newly banned, same expiry.
	u2, b2 := s.Record(KindAccess, "1.1.1.1", lim, now.Add(time.Second))
	assert.False(t, b2)
	assert.Equal(t, until, u2)
}

func TestKindsAndIPsAreIndependent(t *testing.T) {
	s := NewState()
	now := time.Unix(1000, 0)
	lim := Limit{Requests: 3, WindowSec: 10, BanSec: 60}
	for i := 0; i < 3; i++ {
		_, b := s.Record(KindAccess, "A", lim, now)
		assert.False(t, b)
		_, b = s.Record(KindAttack, "A", lim, now)
		assert.False(t, b)
		_, b = s.Record(KindAccess, "B", lim, now)
		assert.False(t, b)
	}
	assert.Empty(t, s.Bans(now))
}

func TestPreviousWindowWeighting(t *testing.T) {
	s := NewState()
	lim := Limit{Requests: 4, WindowSec: 10, BanSec: 60}
	t0 := time.Unix(1000, 0)
	for i := 0; i < 4; i++ {
		s.Record(KindAccess, "x", lim, t0)
	}
	_, b := s.Record(KindAccess, "x", lim, t0.Add(11*time.Second)) // 4*0.9+1 = 4.6 > 4
	assert.True(t, b)
}

func TestPreviousWindowDecaysAndSkippedWindowForgets(t *testing.T) {
	lim := Limit{Requests: 4, WindowSec: 10, BanSec: 60}
	t0 := time.Unix(1000, 0)

	// Late in the next window prev weight is small: 4*0.1+1 = 1.4 <= 4.
	s := NewState()
	for i := 0; i < 4; i++ {
		s.Record(KindAccess, "x", lim, t0)
	}
	_, b := s.Record(KindAccess, "x", lim, t0.Add(19*time.Second))
	assert.False(t, b)

	// Two windows later prev is dropped entirely: estimate 1.
	s = NewState()
	for i := 0; i < 4; i++ {
		s.Record(KindAccess, "x", lim, t0)
	}
	_, b = s.Record(KindAccess, "x", lim, t0.Add(20*time.Second))
	assert.False(t, b)
}

func TestUnbanAndBansList(t *testing.T) {
	s := NewState()
	now := time.Unix(1000, 0)
	lim := Limit{Requests: 1, WindowSec: 10, BanSec: 60}
	s.Record(KindAttack, "9.9.9.9", lim, now)
	until, b := s.Record(KindAttack, "9.9.9.9", lim, now)
	assert.True(t, b)
	assert.Equal(t, map[string]time.Time{"9.9.9.9": until}, s.Bans(now))
	assert.True(t, s.Unban("9.9.9.9"))
	assert.Empty(t, s.Bans(now))
	assert.False(t, s.Unban("9.9.9.9"))
	_, banned := s.BannedUntil("9.9.9.9", now)
	assert.False(t, banned)
}

func TestSweepDropsExpired(t *testing.T) {
	s := NewState()
	now := time.Unix(1000, 0)
	lim := Limit{Requests: 1, WindowSec: 10, BanSec: 60}
	s.Record(KindAccess, "1.2.3.4", lim, now)
	s.Record(KindAccess, "1.2.3.4", lim, now) // banned until 1060
	s.Record(KindAccess, "5.6.7.8", lim, now) // idle window only

	s.Sweep(now.Add(30 * time.Second)) // ban still live, windows idle (30 > 20)
	assert.Len(t, s.Bans(now.Add(30*time.Second)), 1)
	s.mu.Lock()
	assert.Empty(t, s.windows)
	assert.Len(t, s.bans, 1)
	s.mu.Unlock()

	s.Sweep(now.Add(61 * time.Second))
	assert.Empty(t, s.Bans(now))
	s.mu.Lock()
	assert.Empty(t, s.bans)
	s.mu.Unlock()
}

func TestWeightClampedWhenWindowGrows(t *testing.T) {
	s := NewState()
	small := Limit{Requests: 6, WindowSec: 10, BanSec: 60}
	for i := 0; i < 4; i++ {
		s.Record(KindAccess, "x", small, time.Unix(1000, 0)) // window [1000,1010): cur=4
	}
	_, b := s.Record(KindAccess, "x", small, time.Unix(1010, 0)) // rotate: prev=4, cur=1 → 5
	assert.False(t, b)

	// Reload grows the window to 60 s and the clock steps back 2 s: ws=960 does
	// not pass start=1010, so elapsed is -2 s. Unclamped weight would be
	// 1+2/60 and the estimate 2+4*1.033 = 6.13 > 6 (ban); clamped it is 2+4 = 6.
	big := Limit{Requests: 6, WindowSec: 60, BanSec: 60}
	_, b = s.Record(KindAccess, "x", big, time.Unix(1008, 0))
	assert.False(t, b)
}
