/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012  Casey Marshall

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

package sks

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/tomb.v2"

	cf "gopkg.in/hockeypuck/conflux.v2"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	"gopkg.in/hockeypuck/conflux.v2/recon/leveldb"
	"gopkg.in/hockeypuck/hkp.v1/storage"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v1"
)

const requestChunkSize = 100

const maxKeyRecoveryAttempts = 10

type keyRecoveryCounter map[string]int

type Peer struct {
	peer     *recon.Peer
	storage  storage.Storage
	settings *recon.Settings
	ptree    recon.PrefixTree

	path  string
	stats *Stats

	t tomb.Tomb
}

func NewPrefixTree(path string, s *recon.Settings) (recon.PrefixTree, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Debugf("creating prefix tree at: %q", path)
		err = os.MkdirAll(path, 0755)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return leveldb.New(s.PTreeConfig, path)
}

func NewPeer(st storage.Storage, path string, s *recon.Settings) (*Peer, error) {
	if s == nil {
		s = recon.DefaultSettings()
	}

	ptree, err := NewPrefixTree(path, s)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	err = ptree.Create()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	peer := recon.NewPeer(s, ptree)
	sksPeer := &Peer{
		ptree:    ptree,
		storage:  st,
		settings: s,
		peer:     peer,
		path:     path,
	}
	sksPeer.readStats()
	st.Subscribe(sksPeer.updateDigests)
	return sksPeer, nil
}

func StatsFilename(path string) string {
	dir, base := filepath.Dir(path), filepath.Base(path)
	return filepath.Join(dir, "."+base+".stats")
}

func (p *Peer) readStats() {
	fn := StatsFilename(p.path)
	stats := NewStats()
	err := stats.ReadFile(fn)
	if err != nil {
		log.Warningf("cannot open stats %q: %v", fn, err)
		stats = NewStats()
	}

	root, err := p.ptree.Root()
	if err != nil {
		log.Warningf("error accessing prefix tree root: %v", err)
	} else {
		stats.Total = root.Size()
	}

	p.stats = stats
}

func (p *Peer) writeStats() {
	fn := StatsFilename(p.path)
	err := p.stats.WriteFile(fn)
	if err != nil {
		log.Warningf("cannot write stats %q: %v", fn, err)
	}
}

func (p *Peer) pruneStats() error {
	timer := time.NewTimer(time.Hour)
	for {
		select {
		case <-p.t.Dying():
			return nil
		case <-timer.C:
			p.stats.prune()
			timer.Reset(time.Hour)
		}
	}
}

func (r *Peer) Stats() *Stats {
	return r.stats.clone()
}

func (r *Peer) Start() {
	r.t.Go(r.handleRecovery)
	r.t.Go(r.pruneStats)
	r.peer.Start()
}

func (r *Peer) Stop() {
	log.Info("recon processing: stopping")
	r.t.Kill(nil)
	err := r.t.Wait()
	if err != nil {
		log.Error(errgo.Details(err))
	}
	log.Info("recon processing: stopped")

	log.Info("recon peer: stopping")
	err = errgo.Mask(r.peer.Stop())
	if err != nil {
		log.Error(errgo.Details(err))
	}
	log.Info("recon peer: stopped")

	err = r.ptree.Close()
	if err != nil {
		log.Errorf("error closing prefix tree: %v", errgo.Details(err))
	}

	r.writeStats()
}

func DigestZp(digest string) (*cf.Zp, error) {
	buf, err := hex.DecodeString(digest)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	buf = recon.PadSksElement(buf)
	return cf.Zb(cf.P_SKS, buf), nil
}

func (r *Peer) updateDigests(change storage.KeyChange) error {
	r.stats.Update(change)
	for _, digest := range change.InsertDigests() {
		digestZp, err := DigestZp(digest)
		if err != nil {
			return errgo.Notef(err, "bad digest %q", digest)
		}
		r.peer.Insert(digestZp)
	}
	for _, digest := range change.RemoveDigests() {
		digestZp, err := DigestZp(digest)
		if err != nil {
			return errgo.Notef(err, "bad digest %q", digest)
		}
		r.peer.Remove(digestZp)
	}
	return nil
}

func (r *Peer) handleRecovery() error {
	for {
		select {
		case <-r.t.Dying():
			return nil
		case rcvr := <-r.peer.RecoverChan:
			r.requestRecovered(rcvr)
		}
	}
}

func (r *Peer) requestRecovered(rcvr *recon.Recover) error {
	items := rcvr.RemoteElements
	var resultErr error
	for len(items) > 0 {
		// Chunk requests to keep the hashquery message size and peer load reasonable.
		chunksize := requestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]
		items = items[chunksize:]

		err := r.requestChunk(rcvr, chunk)
		if err != nil {
			if resultErr == nil {
				resultErr = errgo.Mask(err)
			} else {
				resultErr = errgo.Notef(resultErr, "%s", errgo.Details(err))
			}
		}
	}
	return resultErr
}

func (r *Peer) requestChunk(rcvr *recon.Recover, chunk []*cf.Zp) error {
	var remoteAddr string
	remoteAddr, err := rcvr.HkpAddr()
	if err != nil {
		return errgo.Mask(err)
	}
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(chunk))
	if err != nil {
		return errgo.Mask(err)
	}
	for _, z := range chunk {
		zb := z.Bytes()
		zb = recon.PadSksElement(zb)
		// Hashquery elements are 16 bytes (length_of(P_SKS)-1)
		zb = zb[:len(zb)-1]
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return errgo.Mask(err)
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return errgo.Mask(err)
		}
	}

	url := fmt.Sprintf("http://%s/pks/hashquery", remoteAddr)
	resp, err := http.Post(url, "sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
	if err != nil {
		return errgo.Mask(err)
	}

	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	bodyBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errgo.Mask(err)
	}
	body = bytes.NewBuffer(bodyBuf)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errgo.Newf("error response from %q: %v", remoteAddr, string(bodyBuf))
	}

	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(body)
	if err != nil {
		return errgo.Mask(err)
	}
	log.Debugf("hashquery response from %q: %d keys found", remoteAddr, nkeys)
	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(body)
		if err != nil {
			return errgo.Mask(err)
		}
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, body, int64(keyLen))
		if err != nil {
			return errgo.Mask(err)
		}
		log.Debugf("key# %d: %d bytes", i+1, keyLen)
		// Merge locally
		err = r.upsertKeys(keyBuf.Bytes())
		if err != nil {
			log.Errorf("cannot upsert: %v", err)
		}
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return nil
}

func (r *Peer) upsertKeys(buf []byte) error {
	for readKey := range openpgp.ReadKeys(bytes.NewBuffer(buf)) {
		if readKey.Error != nil {
			return errgo.Mask(readKey.Error)
		}
		// TODO: collect duplicates to replicate SKS hashes?
		err := openpgp.DropDuplicates(readKey.PrimaryKey)
		if err != nil {
			return errgo.Mask(err)
		}
		_, err = storage.UpsertKey(r.storage, readKey.PrimaryKey)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}
