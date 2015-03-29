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
	"encoding/json"
	"os"
	"sync"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/hkp.v1/storage"
)

type LoadStat struct {
	Inserted int
	Updated  int
}

type LoadStatMap map[time.Time]*LoadStat

func (m LoadStatMap) MarshalJSON() ([]byte, error) {
	doc := map[string]*LoadStat{}
	for k, v := range m {
		doc[k.Format(time.RFC3339)] = v
	}
	return json.Marshal(&doc)
}

func (m LoadStatMap) UnmarshalJSON(b []byte) error {
	doc := map[string]*LoadStat{}
	err := json.Unmarshal(b, &doc)
	if err != nil {
		return err
	}
	for k, v := range doc {
		t, err := time.Parse(time.RFC3339, k)
		if err != nil {
			return err
		}
		m[t] = v
	}
	return nil
}

func (m LoadStatMap) update(t time.Time, kc storage.KeyChange) {
	ls, ok := m[t]
	if !ok {
		ls = &LoadStat{}
		m[t] = ls
	}
	switch kc.(type) {
	case storage.KeyAdded:
		ls.Inserted++
	case storage.KeyReplaced:
		ls.Updated++
	}
}

type Stats struct {
	Total int

	mu     sync.Mutex
	Hourly LoadStatMap
	Daily  LoadStatMap
}

func NewStats() *Stats {
	return &Stats{
		Hourly: LoadStatMap{},
		Daily:  LoadStatMap{},
	}
}

func (s *Stats) prune() {
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	lastWeek := time.Now().UTC().Add(-24 * 7 * time.Hour)
	s.mu.Lock()
	for k := range s.Hourly {
		if k.Before(yesterday) {
			delete(s.Hourly, k)
		}
	}
	for k := range s.Daily {
		if k.Before(lastWeek) {
			delete(s.Daily, k)
		}
	}
	s.mu.Unlock()
}

func (s *Stats) Update(kc storage.KeyChange) {
	s.mu.Lock()
	s.Hourly.update(time.Now().UTC().Truncate(time.Hour), kc)
	s.Daily.update(time.Now().UTC().Truncate(24*time.Hour), kc)
	switch kc.(type) {
	case storage.KeyAdded:
		s.Total++
	}
	s.mu.Unlock()
}

func (s *Stats) clone() *Stats {
	s.mu.Lock()
	result := &Stats{
		Total:  s.Total,
		Hourly: LoadStatMap{},
		Daily:  LoadStatMap{},
	}
	for k, v := range s.Hourly {
		result.Hourly[k] = v
	}
	for k, v := range s.Daily {
		result.Daily[k] = v
	}
	s.mu.Unlock()
	return result
}

func (s *Stats) ReadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			empty := NewStats()
			*s = *empty
			return nil
		} else {
			return errgo.Notef(err, "cannot open stats %q", path)
		}
	} else {
		defer f.Close()
		err = json.NewDecoder(f).Decode(s)
		if err != nil {
			return errgo.Notef(err, "cannot decode stats")
		}
	}
	return nil
}

func (s *Stats) WriteFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return errgo.Notef(err, "cannot open stats %q", path)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(s)
	if err != nil {
		return errgo.Notef(err, "cannot encode stats")
	}
	return nil
}
