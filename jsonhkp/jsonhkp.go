// Package jsonhkp defines an arbitrary, Hockeypuck-specific, JSON-friendly
// document model for representation of OpenPGP key material. Intended to be
// used by front-end Javascript as well as server-side HTML template developers.
package jsonhkp

import (
	"time"

	"gopkg.in/hockeypuck/openpgp.v0"
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

type publicKey struct {
	Fingerprint  string       `json:"fingerprint"`
	LongKeyID    string       `json:"longKeyID"`
	ShortKeyID   string       `json:"shortKeyID"`
	Creation     string       `json:"creation,omitempty"`
	Expiration   string       `json:"expiration,omitempty"`
	NeverExpires bool         `json:"neverExpires,omitempty"`
	Algorithm    int          `json:"algorithm"`
	BitLength    int          `json:"bitLength"`
	Signatures   []*Signature `json:"signatures,omitempty"`
	Unsupported  []*Packet    `json:"unsupported,omitempty"`
	Packet       *Packet      `json:"packet,omitempty"`
}

func newPublicKey(from *openpgp.PublicKey) *publicKey {
	to := &publicKey{
		Fingerprint: from.QualifiedFingerprint(),
		LongKeyID:   from.KeyID(),
		ShortKeyID:  from.ShortID(),
		Algorithm:   from.Algorithm,
		BitLength:   from.BitLen,
		Packet:      NewPacket(&from.Packet),
	}

	if !from.Creation.IsZero() {
		// can happen if openpgp.v0 isn't able to parse this type of key
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
		// can happen if openpgp.v0 isn't able to parse this type of signature
		to.Creation = from.Creation.UTC().Format(time.RFC3339)
	}

	if !from.Expiration.IsZero() {
		to.Expiration = from.Expiration.UTC().Format(time.RFC3339)
	} else {
		to.NeverExpires = true
	}

	return to
}
