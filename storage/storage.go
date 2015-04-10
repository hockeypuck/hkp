/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package storage

import (
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/errgo.v1"

	"gopkg.in/hockeypuck/openpgp.v1"
)

var ErrKeyNotFound = errors.New("key not found")

func IsNotFound(err error) bool {
	return err == ErrKeyNotFound
}

type Keyring struct {
	*openpgp.PrimaryKey

	CTime time.Time
	MTime time.Time
}

// Storage defines the API that is needed to implement a complete storage
// backend for an HKP service.
type Storage interface {
	io.Closer
	Queryer
	Updater
	Notifier
}

// Queryer defines the storage API for search and retrieval of public key material.
type Queryer interface {

	// MatchMD5 returns the matching RFingerprint IDs for the given public key MD5 hashes.
	// The MD5 is calculated using the "SKS method".
	MatchMD5([]string) ([]string, error)

	// MatchID returns the matching RFingerprint IDs for the given public key IDs.
	// Key IDs may be short (last 4 bytes), long (last 10 bytes) or full (20 byte)
	// hexadecimal key IDs.
	Resolve([]string) ([]string, error)

	// MatchKeyword returns the matching RFingerprint IDs for the given keyword search.
	// The keyword search is storage dependant and results may vary among
	// different implementations.
	MatchKeyword([]string) ([]string, error)

	// ModifiedSince returns matching RFingerprint IDs for keyrings modified
	// since the given time.
	ModifiedSince(time.Time) ([]string, error)

	// FetchKeys returns the public key material matching the given RFingerprint slice.
	FetchKeys([]string) ([]*openpgp.PrimaryKey, error)

	// FetchKeyrings returns the keyring records matching the given RFingerprint slice.
	FetchKeyrings([]string) ([]*Keyring, error)
}

// Inserter defines the storage API for inserting key material.
type Inserter interface {

	// Insert inserts new public keys if they are not already stored. If they
	// are, then nothing is changed.
	Insert([]*openpgp.PrimaryKey) (int, error)
}

// Updater defines the storage API for writing key material.
type Updater interface {
	Inserter

	// Update updates the stored PrimaryKey with the given contents, if the current
	// contents of the key in storage matches the given digest. If it does not
	// match, the update should be retried again later.
	Update(pubkey *openpgp.PrimaryKey, priorMD5 string) error
}

type Notifier interface {
	// Subscribe registers a key change callback function.
	Subscribe(func(KeyChange) error)

	// Notify invokes all registered callbacks with a key change notification.
	Notify(change KeyChange) error

	// RenotifyAll() invokes all registered callbacks with KeyAdded notifications
	// for each key in the Storage.
	RenotifyAll() error
}

type KeyChange interface {
	InsertDigests() []string
	RemoveDigests() []string
}

type KeyAdded struct {
	Digest string
}

func (ka KeyAdded) InsertDigests() []string {
	return []string{ka.Digest}
}

func (ka KeyAdded) RemoveDigests() []string {
	return nil
}

func (ka KeyAdded) String() string {
	return fmt.Sprintf("key %q added", ka.Digest)
}

type KeyReplaced struct {
	OldDigest string
	NewDigest string
}

func (kr KeyReplaced) InsertDigests() []string {
	return []string{kr.NewDigest}
}

func (kr KeyReplaced) RemoveDigests() []string {
	return []string{kr.OldDigest}
}

func (kr KeyReplaced) String() string {
	return fmt.Sprintf("key %q replaced %q", kr.NewDigest, kr.OldDigest)
}

type KeyNotChanged struct{}

func (knc KeyNotChanged) InsertDigests() []string { return nil }

func (knc KeyNotChanged) RemoveDigests() []string { return nil }

func (knc KeyNotChanged) String() string {
	return "key not changed"
}

type InsertError struct {
	Duplicates []*openpgp.PrimaryKey
	Errors     []error
}

func (err InsertError) Error() string {
	return fmt.Sprintf("%d duplicates, %d errors", len(err.Duplicates), len(err.Errors))
}

func Duplicates(err error) []*openpgp.PrimaryKey {
	insertErr, ok := err.(InsertError)
	if !ok {
		return nil
	}
	return insertErr.Duplicates
}

func firstMatch(results []*openpgp.PrimaryKey, match string) (*openpgp.PrimaryKey, error) {
	for _, key := range results {
		if key.RFingerprint == match {
			return key, nil
		}
	}
	return nil, ErrKeyNotFound
}

func UpsertKey(storage Storage, pubkey *openpgp.PrimaryKey) (kc KeyChange, err error) {
	var lastKey *openpgp.PrimaryKey
	lastKeys, err := storage.FetchKeys([]string{pubkey.RFingerprint})
	if err == nil {
		// match primary fingerprint -- someone might have reused a subkey somewhere
		lastKey, err = firstMatch(lastKeys, pubkey.RFingerprint)
	}
	if IsNotFound(err) {
		_, err = storage.Insert([]*openpgp.PrimaryKey{pubkey})
		if err != nil {
			return nil, errgo.Mask(err)
		}
		return KeyAdded{Digest: pubkey.MD5}, nil
	} else if err != nil {
		return nil, errgo.Mask(err)
	}

	if pubkey.UUID != lastKey.UUID {
		return nil, errgo.Newf("upsert key %q lookup failed, found mismatch %q", pubkey.UUID, lastKey.UUID)
	}
	lastMD5 := lastKey.MD5
	err = openpgp.Merge(lastKey, pubkey)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	if lastMD5 != lastKey.MD5 {
		err = storage.Update(lastKey, lastMD5)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		return KeyReplaced{OldDigest: lastMD5, NewDigest: lastKey.MD5}, nil
	}
	return KeyNotChanged{}, nil
}
