// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCABundle decodes every CERTIFICATE block in bundlePEM, in file order.
//
// Non-CERTIFICATE blocks are skipped rather than rejected: an operator pasting
// a bundle exported from another tool may legitimately carry comments or a
// trailing key block, and refusing the whole file over an ignorable block would
// be unhelpful. A bundle containing no certificates at all is an error.
func ParseCABundle(bundlePEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in bundle: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("bundle contains no CERTIFICATE blocks")
	}
	return certs, nil
}

// ValidateCABundleOrder checks that certs is a complete certificate chain
// ordered nearest-first: certs[0] is this CA's own signing certificate, each
// entry is issued by the next, and the last is a self-signed root.
//
// The ordering is not a stylistic preference. loadCA parses only the first PEM
// block of the stored bundle and pins the CA key to it, so a bundle in any
// other order fails at startup. GET /certificate/ca serves the blob verbatim,
// and that order is what a Puppet agent expects in its localcacert.
//
// A complete chain to a self-signed root is mandatory. Allowing a bundle to
// stop at an intermediate would leave the CRL chain unverifiable (nothing in
// the bundle could check the root's CRL, which is the one an agent most needs
// for full-chain revocation checking) and would make an export scope promising
// a trust anchor return an intermediate instead.
func ValidateCABundleOrder(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("bundle contains no certificates")
	}

	if !certs[0].IsCA {
		return fmt.Errorf("first certificate in bundle (%q) is not a CA certificate (IsCA=false); "+
			"the bundle must start with this CA's own signing certificate",
			certs[0].Subject.CommonName)
	}

	for i := 0; i < len(certs)-1; i++ {
		child, parent := certs[i], certs[i+1]
		if !parent.IsCA {
			return fmt.Errorf("certificate %d in bundle (%q) is not a CA certificate but is used as an issuer",
				i+2, parent.Subject.CommonName)
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("certificate %d in bundle (%q) is not signed by certificate %d (%q): %w; "+
				"the bundle must be ordered nearest-first, ending with the root",
				i+1, child.Subject.CommonName, i+2, parent.Subject.CommonName, err)
		}
	}

	root := certs[len(certs)-1]
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("the last certificate in the bundle (%q) is not self-signed, so the chain does not "+
			"reach a root; supply the complete chain including the root certificate", root.Subject.CommonName)
	}

	return nil
}
