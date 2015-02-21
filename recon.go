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

package hkp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/errgo.v1"
	cf "gopkg.in/hockeypuck/conflux.v2"
	"gopkg.in/hockeypuck/conflux.v2/recon"
	"gopkg.in/hockeypuck/conflux.v2/recon/leveldb"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v0"
	"gopkg.in/tomb.v2"

	"github.com/hockeypuck/hockeypuck"
)

const requestChunkSize = 100

const maxKeyRecoveryAttempts = 10

type keyRecoveryCounter map[string]int

type SKSPeer struct {
	peer       *recon.Peer
	storage    Storage
	settings   *hockeypuck.Settings
	ptree      recon.PrefixTree
	keyChanges chan KeyChange

	t tomb.Tomb

	mu              sync.Mutex
	recoverAttempts keyRecoveryCounter
}

func newSksPTree(s *hockeypuck.Settings) (recon.PrefixTree, error) {
	if _, err := os.Stat(s.Conflux.Recon.LevelDB.Path); os.IsNotExist(err) {
		log.Debugf("creating prefix tree at: %q", s.Conflux.Recon.LevelDB.Path)
		err = os.MkdirAll(s.Conflux.Recon.LevelDB.Path, 0755)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}
	return leveldb.New(s.Conflux.Recon.PTreeConfig, s.Conflux.Recon.LevelDB.Path)
}

func NewSKSPeer(storage Storage, s *hockeypuck.Settings) (*SKSPeer, error) {
	ptree, err := newSksPTree(s)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	err = ptree.Create()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	peer := recon.NewPeer(&s.Conflux.Recon.Settings, ptree)
	sksPeer := &SKSPeer{
		ptree:           ptree,
		storage:         storage,
		settings:        s,
		peer:            peer,
		keyChanges:      make(chan KeyChange),
		recoverAttempts: make(keyRecoveryCounter),
	}
	return sksPeer, nil
}

func (r *SKSPeer) Start() {
	r.t.Go(r.handleRecovery)
	r.t.Go(r.handleKeyChanges)
	r.peer.Start()
}

func (r *SKSPeer) Stop() {
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
}

func DigestZp(digest string) (*cf.Zp, error) {
	buf, err := hex.DecodeString(digest)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	buf = recon.PadSksElement(buf)
	return cf.Zb(cf.P_SKS, buf), nil
}

func (r *SKSPeer) notifyKeyChange(change KeyChange) {
	if r != nil {
		r.keyChanges <- change
	}
}

func (r *SKSPeer) handleKeyChanges() error {
	for {
		select {
		case <-r.t.Dying():
			return nil
		case keyChange := <-r.keyChanges:
			err := r.updateDigests(keyChange)
			if err != nil {
				return err
			}
		}
	}
}

func (r *SKSPeer) clearRecoverAttempts(z *cf.Zp) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.recoverAttempts, z.String())
}

func (r *SKSPeer) updateDigests(change KeyChange) error {
	for _, digest := range change.InsertDigests() {
		digestZp, err := DigestZp(digest)
		if err != nil {
			return errgo.Notef(err, "bad digest %q", digest)
		}
		log.Debugf("insert into prefix tree: %q", digest)
		r.peer.InsertWith(func(err error) {
			if err != nil {
				log.Errorf("insert %q failed: %v", digest, err)
			}
			r.clearRecoverAttempts(digestZp)
		}, digestZp)
	}

	for _, digest := range change.RemoveDigests() {
		digestZp, err := DigestZp(digest)
		if err != nil {
			return errgo.Notef(err, "bad digest %q", digest)
		}
		log.Debugf("remove from prefix tree: %q", digest)
		r.peer.RemoveWith(func(err error) {
			if err != nil {
				log.Errorf("remove %q failed: %v", digest, err)
			}
		}, digestZp)
	}

	return nil
}

func (r *SKSPeer) handleRecovery() error {
	rcvrChans := make(map[string]chan *recon.Recover)
	defer func() {
		for _, ch := range rcvrChans {
			close(ch)
		}
	}()
	for {
		select {
		case <-r.t.Dying():
			return nil
		case rcvr, ok := <-r.peer.RecoverChan:
			if !ok {
				return nil
			}

			// Use remote HKP host:port as peer-unique identifier
			remoteAddr, err := rcvr.HkpAddr()
			if err != nil {
				continue
			}

			// Mux recoveries to per-address channels
			rcvrChan, has := rcvrChans[remoteAddr]
			if !has {
				rcvrChan = make(chan *recon.Recover)
				rcvrChans[remoteAddr] = rcvrChan
				go r.handleRemoteRecovery(rcvr, rcvrChan)
			}
			rcvrChan <- rcvr
		}
	}
}

type workRecoveredReady chan interface{}
type workRecoveredWork chan *cf.ZSet

func (r *SKSPeer) handleRemoteRecovery(rcvr *recon.Recover, rcvrChan chan *recon.Recover) {
	recovered := cf.NewZSet()
	ready := make(workRecoveredReady)
	work := make(workRecoveredWork)
	defer close(work)
	go r.workRecovered(rcvr, ready, work)
	for {
		select {
		case <-r.t.Dying():
			return
		case rcvr, ok := <-rcvrChan:
			if !ok {
				return
			}
			// Aggregate recovered IDs
			recovered.AddSlice(rcvr.RemoteElements)
			log.Debugf("recovery from %q: %d keys pending", rcvr.RemoteAddr.String(), recovered.Len())
			r.peer.Disable()
		case _, ok := <-ready:
			// Recovery worker is ready for more
			if !ok {
				return
			}
			work <- recovered
			recovered = cf.NewZSet()
		}
	}
}

func (r *SKSPeer) workRecovered(rcvr *recon.Recover, ready workRecoveredReady, work workRecoveredWork) {
	defer close(ready)
	timer := time.NewTimer(time.Duration(3) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-r.t.Dying():
			return
		case recovered, ok := <-work:
			go func() {
				defer r.peer.Enable()
				if !ok {
					return
				}
				err := r.requestRecovered(rcvr, recovered)
				if err != nil {
					log.Warn(err)
				}
				timer.Reset(time.Duration(r.settings.Conflux.Recon.GossipIntervalSecs) * time.Second)
			}()
		case <-timer.C:
			timer.Stop()
			ready <- new(interface{})
		}
	}
}

func (r *SKSPeer) requestRecovered(rcvr *recon.Recover, elements *cf.ZSet) error {
	items := elements.Items()
	var resultErr error
	for len(items) > 0 {
		// Chunk requests to keep the hashquery message size and peer load reasonable.
		chunksize := requestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]
		items = items[chunksize:]
		r.countChunk(chunk)
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

func (r *SKSPeer) incrementRecoverAttempts(z *cf.Zp) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recoverAttempts[z.String()]++
	return r.recoverAttempts[z.String()]
}

func (r *SKSPeer) countChunk(chunk []*cf.Zp) {
	for _, z := range chunk {
		n := r.incrementRecoverAttempts(z)
		if n > maxKeyRecoveryAttempts {
			log.Warnf("giving up on key %q after failing to recover %d attempts", z, n)
			r.peer.InsertWith(func(err error) {
				if err != nil {
					log.Errorf("failed to insert %s into prefix tree to prevent further attempts", z)
				}
			}, z)
		}
	}
}

func (r *SKSPeer) requestChunk(rcvr *recon.Recover, chunk []*cf.Zp) error {
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
	resp, err := http.Post(fmt.Sprintf("http://%s/pks/hashquery", remoteAddr),
		"sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
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
			return errgo.Mask(err)
		}
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return nil
}

func (r *SKSPeer) upsertKeys(buf []byte) error {
	for readKey := range openpgp.ReadKeys(bytes.NewBuffer(buf)) {
		if readKey.Error != nil {
			return errgo.Mask(readKey.Error)
		}
		err := openpgp.CollectDuplicates(readKey.Pubkey)
		if err != nil {
			return errgo.Mask(err)
		}
		change, err := UpsertKey(r.storage, readKey.Pubkey)
		if err != nil {
			return errgo.Mask(err)
		}
		r.keyChanges <- change
	}
	return nil
}
