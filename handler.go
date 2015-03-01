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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/openpgp/armor"
	"gopkg.in/errgo.v1"

	"gopkg.in/hockeypuck/conflux.v2/recon"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v0"

	"gopkg.in/hockeypuck/hkp.v0/storage"
)

const (
	shortKeyIDLen       = 8
	longKeyIDLen        = 16
	fingerprintKeyIDLen = 40
)

func httpError(w http.ResponseWriter, statusCode int, err error) {
	if statusCode != http.StatusNotFound {
		log.Errorf("HTTP %d: %v", statusCode, errgo.Details(err))
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

type Handler struct {
	storage storage.Storage
}

type HandlerOption func(h *Handler) error

func NewHandler(storage storage.Storage) *Handler {
	return &Handler{storage: storage}
}

func (h *Handler) Register(r *httprouter.Router) {
	r.GET("/pks/lookup", h.Lookup)
	r.POST("/pks/add", h.Add)
	r.POST("/pks/hashquery", h.HashQuery)
}

func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	l, err := ParseLookup(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	switch l.Op {
	case OperationGet, OperationHGet:
		h.get(w, l)
	case OperationIndex, OperationVIndex:
		h.index(w, l)
	default:
		httpError(w, http.StatusNotFound, errgo.Newf("operation not found: %v", l.Op))
		return
	}
}

func (h *Handler) HashQuery(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	hq, err := ParseHashQuery(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}
	var result []*openpgp.Pubkey
	for _, digest := range hq.Digests {
		rfps, err := h.storage.MatchMD5([]string{digest})
		if err != nil {
			log.Errorf("error resolving hashquery digest %q", digest)
			continue
		}
		keys, err := h.storage.FetchKeys(rfps)
		if err != nil {
			log.Errorf("error fetching hashquery key %q", digest)
			continue
		}
		result = append(result, keys...)
	}

	w.Header().Set("Content-Type", "pgp/keys")

	// Write the number of keys
	err = recon.WriteInt(w, len(result))
	for _, key := range result {
		// Write each key in binary packet format, prefixed with length
		err = writeHashqueryKey(w, key)
		if err != nil {
			log.Errorf("error writing hashquery key %q: %v", key.RFingerprint, err)
			return
		}
	}

	// SKS expects hashquery response to terminate with a CRLF
	_, err = w.Write([]byte{0x0d, 0x0a})
	if err != nil {
		log.Errorf("error writing hashquery terminator: %v", err)
	}
}

func writeHashqueryKey(w http.ResponseWriter, key *openpgp.Pubkey) error {
	var buf bytes.Buffer
	err := openpgp.WritePackets(&buf, key)
	if err != nil {
		return errgo.Mask(err)
	}
	err = recon.WriteInt(w, buf.Len())
	if err != nil {
		return errgo.Mask(err)
	}
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return errgo.Mask(err)
	}
	return nil
}

func (h *Handler) resolve(l *Lookup) ([]string, error) {
	if l.Op == OperationHGet {
		return h.storage.MatchMD5([]string{l.Search})
	}
	if strings.HasPrefix(l.Search, "0x") {
		keyID := openpgp.Reverse(strings.ToLower(l.Search[2:]))
		switch len(keyID) {
		case shortKeyIDLen, longKeyIDLen, fingerprintKeyIDLen:
			return h.storage.Resolve([]string{keyID})
		}
	}
	return h.storage.MatchKeyword([]string{l.Search})
}

func (h *Handler) keys(l *Lookup) ([]*openpgp.Pubkey, error) {
	rfps, err := h.resolve(l)
	if err != nil {
		return nil, err
	}
	return h.storage.FetchKeys(rfps)
}

func (h *Handler) get(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errgo.New("not found"))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	err = openpgp.WriteArmoredPackets(w, keys)
	if err != nil {
		log.Errorf("get %q: error writing armored keys: %v", l.Search, err)
	}
}

func (h *Handler) index(w http.ResponseWriter, l *Lookup) {
	keys, err := h.keys(l)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
	if len(keys) == 0 {
		httpError(w, http.StatusNotFound, errgo.New("not found"))
		return
	}

	if l.Options[OptionMachineReadable] {
		h.indexMR(w, keys, l)
	} else {
		h.indexJSON(w, keys)
	}
}

func (h *Handler) indexJSON(w http.ResponseWriter, keys []*openpgp.Pubkey) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err := enc.Encode(&keys)
	if err != nil {
		httpError(w, http.StatusInternalServerError, errgo.Mask(err))
		return
	}
}

func mrTimeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d", t.Unix())
}

func (h *Handler) indexMR(w http.ResponseWriter, keys []*openpgp.Pubkey, l *Lookup) {
	w.Header().Set("Content-Type", "text/plain")

	fmt.Fprintf(w, "info:1:%d\n", len(keys))
	for _, key := range keys {
		selfsigs := key.SelfSigs()
		if !selfsigs.Valid() {
			continue
		}

		var keyID string
		if l.Fingerprint {
			keyID = key.Fingerprint()
		} else {
			keyID = key.KeyID()
		}
		keyID = strings.ToUpper(keyID)

		expiresAt, _ := selfsigs.ExpiresAt()

		fmt.Fprintf(w, "pub:%s:%d:%d:%d:%s:\n", keyID, key.Algorithm, key.BitLen,
			key.Creation.Unix(), mrTimeString(expiresAt))

		for _, uid := range key.UserIDs {
			selfsigs := uid.SelfSigs(key)
			validSince, ok := selfsigs.ValidSince()
			if !ok {
				continue
			}
			expiresAt, _ := selfsigs.ExpiresAt()
			fmt.Fprintf(w, "uid:%s:%d:%s:\n", strings.Replace(uid.Keywords, ":", "%3a", -1),
				validSince.Unix(), mrTimeString(expiresAt))
		}
	}
}

type AddResponse struct {
	Inserted []string `json:"inserted"`
	Updated  []string `json:"updated"`
	Ignored  []string `json:"ignored"`
}

func (h *Handler) Add(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	add, err := ParseAdd(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}

	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(add.Keytext))
	if err != nil {
		httpError(w, http.StatusBadRequest, errgo.Mask(err))
		return
	}

	var result AddResponse
	for readKey := range openpgp.ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			httpError(w, http.StatusBadRequest, errgo.Mask(err))
			return
		}
		err := openpgp.DropDuplicates(readKey.Pubkey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errgo.Mask(err))
			return
		}
		change, err := storage.UpsertKey(h.storage, readKey.Pubkey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, errgo.Mask(err))
			return
		}

		fp := readKey.Pubkey.QualifiedFingerprint()
		switch change.(type) {
		case storage.KeyAdded:
			result.Inserted = append(result.Inserted, fp)
		case storage.KeyReplaced:
			result.Updated = append(result.Updated, fp)
		case storage.KeyNotChanged:
			result.Ignored = append(result.Ignored, fp)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(&result)
}
