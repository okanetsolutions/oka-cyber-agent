package main

import (
	"os/user"
	"testing"

	"github.com/okanetsolutions/oka-cyber-agent/internal/config"
)

func TestTokenOwner(t *testing.T) {
	t.Run("installed service account", func(t *testing.T) {
		owner, err := tokenOwner(0, func(name string) (*user.User, error) {
			if name != serviceUser {
				t.Fatalf("looked up %q, want %q", name, serviceUser)
			}
			return &user.User{Uid: "991", Gid: "990"}, nil
		})
		if want := (config.Owner{UID: 991, GID: 990}); err != nil || owner == nil || *owner != want {
			t.Fatalf("tokenOwner = %+v, %v, want %+v", owner, err, want)
		}
	})

	t.Run("standalone root enrollment", func(t *testing.T) {
		owner, err := tokenOwner(0, func(name string) (*user.User, error) {
			return nil, user.UnknownUserError(name)
		})
		if err != nil || owner == nil || *owner != (config.Owner{UID: 0, GID: 0}) {
			t.Fatalf("tokenOwner = %+v, %v, want root ownership", owner, err)
		}
	})

	t.Run("non-root enrollment", func(t *testing.T) {
		owner, err := tokenOwner(1000, func(name string) (*user.User, error) {
			t.Fatalf("unexpected account lookup for %q", name)
			return nil, nil
		})
		if err != nil || owner != nil {
			t.Fatalf("tokenOwner = %+v, %v, want the process owner", owner, err)
		}
	})
}
