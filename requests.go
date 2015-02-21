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
	"encoding/hex"
	"net/http"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2/recon"
)

// Operation enumerates the supported HKP operations (op parameter) in the request.
type Operation string

const (
	OperationGet    = Operation("get")
	OperationIndex  = Operation("index")
	OperationVIndex = Operation("vindex")
	OperationStats  = Operation("stats")
	OperationHGet   = Operation("hget")
)

func ParseOperation(s string) (Operation, bool) {
	op := Operation(s)
	switch op {
	case OperationGet, OperationIndex, OperationVIndex,
		OperationStats, OperationHGet:
		return op, true
	}
	return Operation(""), false
}

// Option defines modifiers available to some HKP requests.
type Option string

const (
	OptionMachineReadable = Option("mr")
	OptionNotModifiable   = Option("nm")
)

type OptionSet map[Option]bool

func ParseOptionSet(s string) OptionSet {
	result := OptionSet{}
	fields := strings.Split(s, ",")
	for _, field := range fields {
		result[Option(field)] = true
	}
	return result
}

// Lookup contains all the parameters and options for a /pks/lookup request.
type Lookup struct {
	Op          Operation
	Search      string
	Options     OptionSet
	Fingerprint bool
	Exact       bool
	Hash        bool
}

func ParseLookup(req *http.Request) (*Lookup, error) {
	err := req.ParseForm()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var l Lookup
	var ok bool
	// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.1.2
	l.Op, ok = ParseOperation(req.Form.Get("op"))
	if !ok {
		return nil, errgo.Newf("invalid operation %q", req.Form.Get("op"))
	}

	if l.Op != OperationStats {
		// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.1.1
		l.Search = req.Form.Get("search")
		if l.Search == "" {
			return nil, errgo.Newf("missing required parameter: search")
		}
	}

	l.Options = ParseOptionSet(req.Form.Get("options"))

	// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.2.2
	l.Fingerprint = req.Form.Get("fingerprint") == "on"

	// Not in draft spec, SKS convention
	l.Hash = req.Form.Get("hash") == "on"

	// OpenPGP HTTP Keyserver Protocol (HKP), Section 3.2.3
	l.Exact = req.Form.Get("exact") == "on"

	return &l, nil
}

// Add represents a valid /pks/add request content, parameters and options.
type Add struct {
	Keytext string
	Options OptionSet
}

func ParseAdd(req *http.Request) (*Add, error) {
	if req.Method != "POST" {
		return nil, errgo.Newf("invalid HTTP method: %s", req.Method)
	}

	var add Add
	// Parse the URL query parameters
	err := req.ParseForm()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	add.Keytext = req.Form.Get("keytext")
	if add.Keytext == "" {
		return nil, errgo.Newf("missing required parameter: keytext")
	}

	add.Options = ParseOptionSet(req.Form.Get("options"))

	return &add, nil
}

type HashQuery struct {
	Digests []string
}

func ParseHashQuery(req *http.Request) (*HashQuery, error) {
	if req.Method != "POST" {
		return nil, errgo.Newf("invalid HTTP method: %s", req.Method)
	}

	r := req.Body
	defer r.Close()

	var hq HashQuery

	// Parse hashquery POST data
	n, err := recon.ReadInt(r)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	hq.Digests = make([]string, n)
	for i := 0; i < n; i++ {
		hashlen, err := recon.ReadInt(r)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		hash := make([]byte, hashlen)
		_, err = r.Read(hash)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		hq.Digests[i] = hex.EncodeToString(hash)
	}

	return &hq, nil
}
