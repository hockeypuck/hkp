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

package hkp

import (
	"errors"

	"github.com/hockeypuck/hockeypuck/openpgp"
)

var ErrKeyNotFound = errors.New("key not found")

func IsNotFound(err error) bool {
	return err == ErrKeyNotFound
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

	// FetchKeys returns the public key packet models matching the given RFingerprint slice.
	FetchKeys([]string) ([]*openpgp.Pubkey, error)
}

// Inserter defines the storage API for inserting key material.
type Inserter interface {

	// Insert inserts new public keys if they are not already stored. If they
	// are, then nothing is changed.
	Insert([]*openpgp.Pubkey) error
}

// Updater defines the storage API for writing key material.
type Updater interface {
	Inserter

	// Update updates the stored Pubkey with the given contents.
	Update(*openpgp.Pubkey) error
}

// Storage defines the API that is needed to implement a complete storage
// backend for an HKP service.
type Storage interface {
	Queryer
	Updater
}
