// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"runtime"
	"unsafe"
)

// CertPool is a set of certificates.
type CertPool struct {
	byName map[string][]int
	// lazyCerts contains funcs that return a certificate,
	// lazily parsing/decompressing it as needed.
	lazyCerts []lazyCert

	// haveSum maps from sum224(cert.Raw) to true. It's used only
	// for AddCert duplicate detection, to avoid CertPool.contains
	// calls in the AddCert path (because the contains method can
	// call getCert and otherwise negate savings from lazy getCert
	// funcs).
	haveSum map[sum224]bool

	// systemPool indicates whether this is a special pool derived from the
	// system roots. If it includes additional roots, it requires doing two
	// verifications, one using the roots provided by the caller, and one using
	// the system platform verifier.
	systemPool bool

	bySubjectKeyId map[string][]int
	certs          []*Certificate
}

type sum224 [sha256.Size224]byte

// lazyCert is minimal metadata about a Cert and a func to retrieve it
// in its normal expanded *Certificate form.
type lazyCert struct {
	// rawSubject is the Certificate.RawSubject value.
	// It's the same as the CertPool.byName key, but in []byte
	// form to make CertPool.Subjects (as used by crypto/tls) do
	// fewer allocations.
	rawSubject []byte

	// getCert returns the certificate.
	//
	// It is not meant to do network operations or anything else
	// where a failure is likely; the func is meant to lazily
	// parse/decompress data that is already known to be good. The
	// error in the signature primarily is meant for use in the
	// case where a cert file existed on local disk when the program
	// started up is deleted later before it's read.
	getCert func() (*Certificate, error)
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{
		bySubjectKeyId: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

func (s *CertPool) copy() *CertPool {
	p := &CertPool{
		bySubjectKeyId: make(map[string][]int, len(s.bySubjectKeyId)),
		byName:         make(map[string][]int, len(s.byName)),
		certs:          make([]*Certificate, len(s.certs)),
	}
	for k, v := range s.bySubjectKeyId {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.bySubjectKeyId[k] = indexes
	}
	for k, v := range s.byName {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.byName[k] = indexes
	}
	copy(p.certs, s.certs)
	return p
}

// SystemCertPool returns a copy of the system cert pool.
//
// On Unix systems other than macOS the environment variables SSL_CERT_FILE and
// SSL_CERT_DIR can be used to override the system default locations for the SSL
// certificate file and SSL certificate files directory, respectively. The
// latter can be a colon-separated list.
//
// Any mutations to the returned pool are not written to disk and do not affect
// any other pool returned by SystemCertPool.
//
// New changes in the system cert pool might not be reflected in subsequent calls.
func SystemCertPool() (*CertPool, error) {
	if runtime.GOOS == "windows" {
		// Issue 16736, 18609:
		return nil, errors.New("crypto/x509: system root pool is not available on Windows")
	}

	if sysRoots := systemRootsPool(); sysRoots != nil {
		return sysRoots.copy(), nil
	}

	return loadSystemRoots()
}

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.
func (s *CertPool) findPotentialParents(cert *Certificate) []int {
	if s == nil {
		return nil
	}

	var candidates []int
	if len(cert.AuthorityKeyId) > 0 {
		candidates = s.bySubjectKeyId[string(cert.AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		candidates = s.byName[string(cert.RawIssuer)]
	}
	return candidates
}

func (s *CertPool) contains(cert *Certificate) bool {
	if s == nil {
		return false
	}

	candidates := s.byName[string(cert.RawSubject)]
	for _, c := range candidates {
		if s.certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a pool.
func (s *CertPool) AddCert(cert *Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}

	// Check that the certificate isn't being added twice.
	if s.contains(cert) {
		return
	}

	n := len(s.certs)
	s.certs = append(s.certs, cert)

	if len(cert.SubjectKeyId) > 0 {
		keyId := string(cert.SubjectKeyId)
		s.bySubjectKeyId[keyId] = append(s.bySubjectKeyId[keyId], n)
	}
	name := string(cert.RawSubject)
	s.byName[name] = append(s.byName[name], n)
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (s *CertPool) Subjects() [][]byte {
	res := make([][]byte, len(s.certs))
	for i, c := range s.certs {
		res[i] = c.RawSubject
	}
	return res
}

func ToStandCertPool(certPool *CertPool) *x509.CertPool {
	return (*x509.CertPool)(unsafe.Pointer(certPool))
}
