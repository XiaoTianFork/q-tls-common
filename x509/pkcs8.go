// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/xiaotianfork/qtls-go1-15/sm2"
	"math/big"
	"reflect"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil
	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey
	case *sm2.PrivateKey:
		privKey.Algo.Algorithm = oidPublicKeyECDSA
		namedCurveOID, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("go-pkcs12: unknown elliptic curve")
		}
		var err error
		if privKey.Algo.Parameters.FullBytes, err = asn1.Marshal(namedCurveOID); err != nil {
			return nil, errors.New("go-pkcs12: failed to embed OID of named curve in PKCS#8: " + err.Error())
		}
		if privKey.PrivateKey, err = MarshalSm2PrivateKey(k); err != nil {
			return nil, errors.New("go-pkcs12: failed to embed EC private key in PKCS#8: " + err.Error())
		}
	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func ParseSm2PrivateKey(privateKeyByte []byte) (*sm2.PrivateKey, error) {
	var privateKey sm2PrivateKey

	if _, err := asn1.Unmarshal(privateKeyByte, &privateKey); err != nil {
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	curve := sm2.P256Sm2()
	k := new(big.Int).SetBytes(privateKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(sm2.PrivateKey)
	priv.Curve = curve
	priv.D = k
	privateKeyBytes := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(privateKey.PrivateKey) > len(privateKeyBytes) {
		if privateKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privateKey.PrivateKey = privateKey.PrivateKey[1:]
	}
	copy(privateKeyBytes[len(privateKeyBytes)-len(privateKey.PrivateKey):], privateKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKeyBytes)
	return priv, nil
}

func ParsePKCS8UnecryptedPrivateKey(der []byte) (*sm2.PrivateKey, error) {
	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(privKey.Algo.Algorithm, oidPublicKeyECDSA) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	return ParseSm2PrivateKey(privKey.PrivateKey)
}
