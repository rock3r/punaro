package postgres

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeDeviceStore struct {
	mu      sync.Mutex
	auth    AuthenticatedDevice
	current bool
	calls   int
}

func (f *fakeDeviceStore) AuthenticateDevice(context.Context, string) (AuthenticatedDevice, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if !f.current {
		return AuthenticatedDevice{}, ErrUnauthenticated
	}
	return f.auth, nil
}

func (f *fakeDeviceStore) DeviceSessionCurrent(context.Context, AuthenticatedDevice) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.current, nil
}

func TestDeviceAuthCacheAndSessionFenceObserveRevocationWithinBound(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store := &fakeDeviceStore{auth: AuthenticatedDevice{PrincipalID: testPrincipalA, LookupID: testPrincipalB, Generation: 1}, current: true}
	cache := newDeviceAuthCache(store, func() time.Time { return now }, 2*time.Second)
	first, err := cache.Authenticate(context.Background(), "opaque-credential")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Authenticate(context.Background(), "opaque-credential"); err != nil || store.calls != 1 {
		t.Fatalf("warm cache calls=%d err=%v", store.calls, err)
	}
	store.current = false
	if _, err := cache.Authenticate(context.Background(), "opaque-credential"); err != nil {
		t.Fatalf("cache revoked before documented bound: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := cache.Authenticate(context.Background(), "opaque-credential"); err == nil {
		t.Fatal("cache retained authorization at revalidation bound")
	}

	store.current = true
	session := cache.NewSession(first)
	if ok, err := session.Current(context.Background()); err != nil || !ok {
		t.Fatalf("fresh session current=%t err=%v", ok, err)
	}
	store.current = false
	now = now.Add(time.Second)
	if ok, err := session.Current(context.Background()); err != nil || !ok {
		t.Fatalf("session revoked before bound current=%t err=%v", ok, err)
	}
	now = now.Add(time.Second)
	if ok, err := session.Current(context.Background()); err != nil || ok {
		t.Fatalf("session remained current at bound current=%t err=%v", ok, err)
	}
}

func TestLocalCredentialInvalidationIsImmediateAndScoped(t *testing.T) {
	now := time.Now()
	store := &fakeDeviceStore{auth: AuthenticatedDevice{PrincipalID: testPrincipalA, LookupID: testPrincipalB, Generation: 1}, current: true}
	cache := newDeviceAuthCache(store, func() time.Time { return now }, 2*time.Second)
	if _, err := cache.Authenticate(context.Background(), "credential-a"); err != nil {
		t.Fatal(err)
	}
	cache.Invalidate(testPrincipalB)
	store.current = false
	if _, err := cache.Authenticate(context.Background(), "credential-a"); err == nil {
		t.Fatal("locally invalidated credential remained cached")
	}
}

func TestDeviceAuthCacheCapacityIsHardBounded(t *testing.T) {
	store := &fakeDeviceStore{auth: AuthenticatedDevice{PrincipalID: testPrincipalA, LookupID: testPrincipalB, Generation: 1}, current: true}
	cache := newDeviceAuthCache(store, time.Now, DeviceRevalidationBound)
	for i := 0; i < maxDeviceAuthCacheEntries+25; i++ {
		if _, err := cache.Authenticate(context.Background(), fmt.Sprintf("credential-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) != maxDeviceAuthCacheEntries {
		t.Fatalf("cache entries=%d, want %d", len(cache.entries), maxDeviceAuthCacheEntries)
	}
}
