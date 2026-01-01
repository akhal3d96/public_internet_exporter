package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func noopPing(context.Context, netip.Addr) bool        { return true }
func alwaysFalsePing(context.Context, netip.Addr) bool { return false }
func slow8888FalsePing(_ context.Context, ip netip.Addr) bool {
	if ip == netip.MustParseAddr("8.8.8.8") {
		time.Sleep(2 * time.Second)
		return false
	}
	return true
}
func slowNoopPing(context.Context, netip.Addr) bool {
	time.Sleep(PingTimeout - (1 * time.Second))
	return true
}

func TestNewExporter_AcceptsIPv4(t *testing.T) {
	t.Parallel()

	e := NewExporter([]netip.Addr{netip.MustParseAddr("8.8.8.8")}, noopPing)
	if e == nil {
		t.Fatalf("expected exporter, got nil")
	}
}

func TestNewExporter_PanicsOnIPv6(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic, got none")
		}
	}()

	_ = NewExporter([]netip.Addr{netip.MustParseAddr("::1")}, noopPing)
}

func TestExporter_CanAccessPublicInternet(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	e := NewExporter([]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
	},
		noopPing)

	if ok := e.canAccessPublicInternet(ctx); !ok {
		t.Fatalf("should be true")
	}
}

func TestExporter_CanNotAccessPublicInternet(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	e := NewExporter([]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
	},
		alwaysFalsePing)

	if ok := e.canAccessPublicInternet(ctx); ok {
		t.Fatalf("should be false")
	}
}

func TestExporter_CanAccessPublicInternetSlow8888(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	e := NewExporter([]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("9.9.9.9"),
	},
		slow8888FalsePing)

	if ok := e.canAccessPublicInternet(ctx); !ok {
		t.Fatalf("should be true")
	}
}

func TestExporter_CanAccessPublicInternetSlowPing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), PingTimeout)
	defer cancel()

	e := NewExporter([]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("9.9.9.9"),
	},
		slowNoopPing)

	if ok := e.canAccessPublicInternet(ctx); !ok {
		t.Fatalf("should be true")
	}
}
