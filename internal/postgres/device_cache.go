package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// DeviceRevalidationBound is the maximum positive-cache and long-lived-session
// delay before remote rotation/revocation forces authentication again.
const DeviceRevalidationBound = 2 * time.Second
const maxDeviceAuthCacheEntries = 1024

type deviceAuthStore interface {
	AuthenticateDevice(context.Context, string) (AuthenticatedDevice, error)
	DeviceSessionCurrent(context.Context, AuthenticatedDevice) (bool, error)
}

type cachedDevice struct {
	auth      AuthenticatedDevice
	expiresAt time.Time
}

// DeviceAuthCache is a short, bounded positive cache. It never stores the raw credential.
type DeviceAuthCache struct {
	mu      sync.Mutex
	store   deviceAuthStore
	now     func() time.Time
	ttl     time.Duration
	entries map[[sha256.Size]byte]cachedDevice
}

// NewDeviceAuthCache creates the production two-second revalidation cache.
func NewDeviceAuthCache(store *Database) *DeviceAuthCache {
	return newDeviceAuthCache(store, time.Now, DeviceRevalidationBound)
}

func newDeviceAuthCache(store deviceAuthStore, now func() time.Time, ttl time.Duration) *DeviceAuthCache {
	if ttl <= 0 || ttl > DeviceRevalidationBound {
		ttl = DeviceRevalidationBound
	}
	return &DeviceAuthCache{store: store, now: now, ttl: ttl, entries: make(map[[sha256.Size]byte]cachedDevice)}
}

// Authenticate returns a cached positive result only before its strict deadline.
func (c *DeviceAuthCache) Authenticate(ctx context.Context, encoded string) (AuthenticatedDevice, error) {
	key := sha256.Sum256([]byte(encoded))
	now := c.now()
	c.mu.Lock()
	entry, found := c.entries[key]
	if found && now.Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.auth, nil
	}
	delete(c.entries, key)
	c.mu.Unlock()
	authenticated, err := c.store.AuthenticateDevice(ctx, encoded)
	if err != nil {
		return AuthenticatedDevice{}, err
	}
	c.mu.Lock()
	for cachedKey, cached := range c.entries {
		if !now.Before(cached.expiresAt) {
			delete(c.entries, cachedKey)
		}
	}
	if len(c.entries) >= maxDeviceAuthCacheEntries {
		var victim [sha256.Size]byte
		var victimEntry cachedDevice
		victimSet := false
		for cachedKey, cached := range c.entries {
			if !victimSet || cached.expiresAt.Before(victimEntry.expiresAt) || (cached.expiresAt.Equal(victimEntry.expiresAt) && bytes.Compare(cachedKey[:], victim[:]) < 0) {
				victim, victimEntry, victimSet = cachedKey, cached, true
			}
		}
		delete(c.entries, victim)
	}
	c.entries[key] = cachedDevice{auth: authenticated, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return authenticated, nil
}

// Invalidate evicts a locally rotated/revoked lookup immediately.
func (c *DeviceAuthCache) Invalidate(lookupID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.auth.LookupID == lookupID {
			delete(c.entries, key)
		}
	}
}

// DeviceSession is a long-lived session fence that must be polled by a notifier.
type DeviceSession struct {
	mu        sync.Mutex
	cache     *DeviceAuthCache
	auth      AuthenticatedDevice
	nextCheck time.Time
	closed    bool
}

// NewSession starts a fence whose first remote revalidation is bounded by the cache TTL.
func (c *DeviceAuthCache) NewSession(authenticated AuthenticatedDevice) *DeviceSession {
	return &DeviceSession{cache: c, auth: authenticated, nextCheck: c.now().Add(c.ttl)}
}

// Current returns false permanently once revocation, expiry, or generation drift is observed.
func (s *DeviceSession) Current(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, nil
	}
	now := s.cache.now()
	if now.Before(s.nextCheck) {
		return true, nil
	}
	current, err := s.cache.store.DeviceSessionCurrent(ctx, s.auth)
	if err != nil {
		return false, err
	}
	if !current {
		s.closed = true
		s.cache.Invalidate(s.auth.LookupID)
		return false, nil
	}
	s.nextCheck = now.Add(s.cache.ttl)
	return true, nil
}
