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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	stdtesting "testing"

	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"github.com/hockeypuck/testing"
	"gopkg.in/hockeypuck/openpgp.v0"

	"gopkg.in/hockeypuck/hkp.v0/storage/mock"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type HandlerSuite struct {
	storage *mock.Storage
	srv     *httptest.Server
}

var _ = gc.Suite(&HandlerSuite{})

func (s *HandlerSuite) SetUpTest(c *gc.C) {
	s.storage = mock.NewStorage(
		mock.Resolve(func([]string) ([]string, error) {
			return []string{"accd0e320f1cb163a2aa9305257f384b1fc8ef01"}, nil
		}),
		mock.FetchKeys(func([]string) ([]*openpgp.Pubkey, error) {
			return openpgp.MustReadArmorKeys(testing.MustInput("alice_signed.asc")).MustParse(), nil
		}),
	)

	r := httprouter.New()
	handler := NewHandler(s.storage)
	handler.Register(r)
	s.srv = httptest.NewServer(r)
}

func (s *HandlerSuite) TearDownTest(c *gc.C) {
	s.srv.Close()
}

func (s *HandlerSuite) TestGetAlice(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x23e0dcca")
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "23e0dcca")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "alice <alice@example.com>")
}

func (s *HandlerSuite) TestIndexAlice(c *gc.C) {
	for _, op := range []string{"index", "vindex"} {
		res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=%s&search=0x23e0dcca", s.srv.URL, op))
		c.Assert(err, gc.IsNil)
		doc, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil)

		var result []map[string]interface{}
		err = json.Unmarshal(doc, &result)
		c.Assert(err, gc.IsNil)

		c.Assert(result, gc.HasLen, 1)
		c.Assert(fmt.Sprintf("%v", result[0]["BitLen"]), gc.Equals, "2048")
	}
}

func (s *HandlerSuite) TestIndexAliceMR(c *gc.C) {
	res, err := http.Get(fmt.Sprintf("%s/pks/lookup?op=vindex&options=mr&search=0x23e0dcca", s.srv.URL))
	c.Assert(err, gc.IsNil)
	doc, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)

	c.Assert(string(doc), gc.Equals, `info:1:1
pub:361BC1F023E0DCCA:1:2048:1345589945::
uid:alice <alice@example.com>:1345589945::
`)
}
