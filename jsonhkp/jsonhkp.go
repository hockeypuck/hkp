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

// Package jsonhkp defines an arbitrary, Hockeypuck-specific, JSON-friendly
// document model for representation of OpenPGP key material. Intended to be
// used by front-end Javascript as well as server-side HTML template developers.
package jsonhkp

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"time"

	"gopkg.in/errgo.v1"

	"gopkg.in/hockeypuck/openpgp.v1"
)

type Packet struct {
	Tag    uint8  `json:"tag"`
	Data   []byte `json:"data"`
	Parsed bool   `json:"parsed"`
}

func NewPacket(from *openpgp.Packet) *Packet {
	return &Packet{
		Tag:    from.Tag,
		Data:   from.Packet,
		Parsed: from.Parsed,
	}
}

type algorithm struct {
	Name string `json:"name"`
	Code int    `json:"code"`
}

type publicKey struct {
	Fingerprint  string       `json:"fingerprint"`
	LongKeyID    string       `json:"longKeyID"`
	ShortKeyID   string       `json:"shortKeyID"`
	Creation     string       `json:"creation,omitempty"`
	Expiration   string       `json:"expiration,omitempty"`
	NeverExpires bool         `json:"neverExpires,omitempty"`
	Algorithm    algorithm    `json:"algorithm"`
	BitLength    int          `json:"bitLength"`
	Signatures   []*Signature `json:"signatures,omitempty"`
	Unsupported  []*Packet    `json:"unsupported,omitempty"`
	Packet       *Packet      `json:"packet,omitempty"`
}

func newPublicKey(from *openpgp.PublicKey) *publicKey {
	to := &publicKey{
		Fingerprint: from.Fingerprint(),
		LongKeyID:   from.KeyID(),
		ShortKeyID:  from.ShortID(),
		Algorithm: algorithm{
			Name: openpgp.AlgorithmName(from.Algorithm),
			Code: from.Algorithm,
		},
		BitLength: from.BitLen,
		Packet:    NewPacket(&from.Packet),
	}

	if !from.Creation.IsZero() {
		// can happen if openpgp.v1 isn't able to parse this type of key
		to.Creation = from.Creation.UTC().Format(time.RFC3339)
	}

	if !from.Expiration.IsZero() {
		to.Expiration = from.Expiration.UTC().Format(time.RFC3339)
	} else {
		to.NeverExpires = true
	}

	for _, fromSig := range from.Signatures {
		to.Signatures = append(to.Signatures, NewSignature(fromSig))
	}
	for _, fromPkt := range from.Others {
		to.Unsupported = append(to.Unsupported, NewPacket(fromPkt))
	}

	return to
}

type PrimaryKey struct {
	*publicKey

	MD5       string           `json:"md5"`
	SHA256    string           `json:"sha256,omitempty"`
	SubKeys   []*SubKey        `json:"subKeys,omitempty"`
	UserIDs   []*UserID        `json:"userIDs,omitempty"`
	UserAttrs []*UserAttribute `json:"userAttrs,omitempty"`
}

func NewPrimaryKeys(froms []*openpgp.PrimaryKey) []*PrimaryKey {
	var result []*PrimaryKey
	for _, from := range froms {
		result = append(result, NewPrimaryKey(from))
	}
	return result
}

func NewPrimaryKey(from *openpgp.PrimaryKey) *PrimaryKey {
	to := &PrimaryKey{
		publicKey: newPublicKey(&from.PublicKey),
		MD5:       from.MD5,
		SHA256:    from.SHA256,
	}
	for _, fromSubKey := range from.SubKeys {
		to.SubKeys = append(to.SubKeys, NewSubKey(fromSubKey))
	}
	for _, fromUid := range from.UserIDs {
		to.UserIDs = append(to.UserIDs, NewUserID(fromUid))
	}
	for _, fromUat := range from.UserAttributes {
		to.UserAttrs = append(to.UserAttrs, NewUserAttribute(fromUat))
	}
	return to
}

func (pk *PrimaryKey) Serialize(w io.Writer) error {
	packets := pk.packets()
	for _, packet := range packets {
		_, err := w.Write(packet.Data)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

type SubKey struct {
	*publicKey
}

func NewSubKey(from *openpgp.SubKey) *SubKey {
	return &SubKey{
		newPublicKey(&from.PublicKey),
	}
}

type UserID struct {
	Keywords    string       `json:"keywords"`
	Packet      *Packet      `json:"packet,omitempty"`
	Signatures  []*Signature `json:"signatures,omitempty"`
	Unsupported []*Packet    `json:"unsupported,omitempty"`
}

func NewUserID(from *openpgp.UserID) *UserID {
	to := &UserID{
		Keywords: from.Keywords,
		Packet:   NewPacket(&from.Packet),
	}
	for _, fromSig := range from.Signatures {
		to.Signatures = append(to.Signatures, NewSignature(fromSig))
	}
	for _, fromPkt := range from.Others {
		to.Unsupported = append(to.Unsupported, NewPacket(fromPkt))
	}
	return to
}

type UserAttribute struct {
	Photos      []*Photo     `json:"photos,omitempty"`
	Packet      *Packet      `json:"packet,omitempty"`
	Signatures  []*Signature `json:"signatures,omitempty"`
	Unsupported []*Packet    `json:"unsupported,omitempty"`
}

func NewUserAttribute(from *openpgp.UserAttribute) *UserAttribute {
	to := &UserAttribute{
		Packet: NewPacket(&from.Packet),
	}
	for _, image := range from.Images {
		to.Photos = append(to.Photos, NewPhoto(image))
	}
	for _, fromSig := range from.Signatures {
		to.Signatures = append(to.Signatures, NewSignature(fromSig))
	}
	for _, fromPkt := range from.Others {
		to.Unsupported = append(to.Unsupported, NewPacket(fromPkt))
	}
	return to
}

type Photo struct {
	MIMEType string `json:"mimeType"`
	Contents []byte `json:"contents"`
}

func NewPhoto(image []byte) *Photo {
	return &Photo{
		MIMEType: "image/jpeg", // The only image format currently supported, AFAIK
		Contents: image,
	}
}

func (p *Photo) DataURI() (*url.URL, error) {
	return url.Parse(fmt.Sprintf(
		"data:%s;base64,%s", p.MIMEType, base64.StdEncoding.EncodeToString(p.Contents)))
}

type Signature struct {
	SigType      int     `json:"sigType"`
	Revocation   bool    `json:"revocation,omitempty"`
	Primary      bool    `json:"primary,omitempty"`
	IssuerKeyID  string  `json:"issuerKeyID,omitempty"`
	Creation     string  `json:"creation,omitempty"`
	Expiration   string  `json:"expiration,omitempty"`
	NeverExpires bool    `json:"neverExpires,omitempty"`
	Packet       *Packet `json:"packet,omitempty"`
}

func NewSignature(from *openpgp.Signature) *Signature {
	to := &Signature{
		Packet:      NewPacket(&from.Packet),
		SigType:     from.SigType,
		IssuerKeyID: from.IssuerKeyID(),
		Primary:     from.Primary,
	}

	switch to.SigType {
	case 0x20, 0x28, 0x30:
		to.Revocation = true
	}

	if !from.Creation.IsZero() {
		// can happen if openpgp.v1 isn't able to parse this type of signature
		to.Creation = from.Creation.UTC().Format(time.RFC3339)
	}

	if !from.Expiration.IsZero() {
		to.Expiration = from.Expiration.UTC().Format(time.RFC3339)
	} else {
		to.NeverExpires = true
	}

	return to
}

func (pk *PrimaryKey) Bytes() []byte {
	var buf []byte
	for _, pkt := range pk.packets() {
		buf = append(buf, pkt.Data...)
	}
	return buf
}

func (s *Signature) packets() []*Packet {
	packets := []*Packet{s.Packet}
	return packets
}

func (pk *publicKey) packets() []*Packet {
	packets := []*Packet{pk.Packet}
	for _, s := range pk.Signatures {
		packets = append(packets, s.packets()...)
	}
	for _, un := range pk.Unsupported {
		packets = append(packets, un)
	}
	return packets
}

func (u *UserID) packets() []*Packet {
	packets := []*Packet{u.Packet}
	for _, s := range u.Signatures {
		packets = append(packets, s.packets()...)
	}
	for _, un := range u.Unsupported {
		packets = append(packets, un)
	}
	return packets
}

func (u *UserAttribute) packets() []*Packet {
	packets := []*Packet{u.Packet}
	for _, s := range u.Signatures {
		packets = append(packets, s.packets()...)
	}
	for _, un := range u.Unsupported {
		packets = append(packets, un)
	}
	return packets
}

func (pk *PrimaryKey) packets() []*Packet {
	packets := pk.publicKey.packets()
	for _, u := range pk.UserIDs {
		packets = append(packets, u.packets()...)
	}
	for _, u := range pk.UserAttrs {
		packets = append(packets, u.packets()...)
	}
	for _, s := range pk.SubKeys {
		packets = append(packets, s.packets()...)
	}
	return packets
}
