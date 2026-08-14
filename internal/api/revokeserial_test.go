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

package api_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("PUT certificate_status_by_serial", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		mux    http.Handler
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-revokeserial-api-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		mux = api.New(myCA).Routes()
	})

	issue := func(subject string) string {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return strings.ToUpper(cert.SerialNumber.Text(16))
	}

	// superseded reproduces the orphan: an issued certificate that a later
	// issuance for the same subject displaced without retiring.
	superseded := func(subject string) string {
		old := issue(subject)
		Expect(store.DeleteCert(ctx, subject)).To(Succeed())
		issue(subject)
		return old
	}

	// crlSerials reads the CRL back through the API, canonically rendered.
	crlSerials := func() []string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil))
		Expect(rec.Code).To(Equal(http.StatusOK))
		block, _ := pem.Decode(rec.Body.Bytes())
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		out := make([]string, 0, len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			out = append(out, strings.ToUpper(e.SerialNumber.Text(16)))
		}
		return out
	}

	put := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	revoke := func(serial, body string) *httptest.ResponseRecorder {
		return put("/puppet-ca/v1/certificate_status_by_serial/"+serial, body)
	}

	It("revokes the serial and answers 204", func() {
		serial := superseded("api-orphan")

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))

		status := httptest.NewRecorder()
		mux.ServeHTTP(status, httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil))
		Expect(status.Code).To(Equal(http.StatusOK))
		block, _ := pem.Decode(status.Body.Bytes())
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.RevokedCertificateEntries).To(HaveLen(1))
		Expect(strings.ToUpper(crl.RevokedCertificateEntries[0].SerialNumber.Text(16))).To(Equal(serial))
	})

	It("is reachable at the bare path as well as the /puppet-ca/v1 prefix", func() {
		serial := superseded("api-bare-path")

		rec := put("/certificate_status_by_serial/"+serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))
	})

	It("answers 409 and names the remedy for the live certificate", func() {
		serial := issue("api-live")

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusConflict))
		Expect(rec.Body.String()).To(ContainSubstring("api-live"))
		Expect(rec.Body.String()).To(ContainSubstring("--certname api-live"))
	})

	It("revokes the live certificate when force is set", func() {
		serial := issue("api-forced")

		rec := revoke(serial, `{"desired_state":"revoked","force":true}`)
		Expect(rec.Code).To(Equal(http.StatusNoContent))

		// This is the one spec here whose subject is a live credential being
		// taken out of circulation, so it asserts which serial went, not merely
		// that the request was accepted.
		Expect(crlSerials()).To(ConsistOf(serial))
	})

	It("carries the diagnosis, not a bare conflict, when the stored CRL is foreign", func() {
		// Same reasoning as the subject-keyed route's spec in api_test.go: the
		// status is 409 either way, so only a body assertion can see a revert.
		// This route matters more for that state than most — the docs now name
		// revocation by serial as the way to retire the certificate a failed
		// clean left behind, and this is the refusal an operator meets first.
		serial := superseded("api-foreign-crl")
		Expect(store.UpdateCRL(ctx, foreignCRL())).To(Succeed())

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusConflict))
		Expect(rec.Body.String()).To(ContainSubstring("needs a restart"))
	})

	It("answers 503 without leaking storage detail when the CA cannot service the request", func() {
		// The default arm. It must not be a 409: the two 409s this route returns
		// both document --force as the way forward, and a transient storage
		// fault answered as "conflict" would send an operator to --force for a
		// reason that was never the live-certificate guard.
		serial := superseded("api-unservable")
		// Corrupt the stored CRL so readStoredCRL fails with something that is
		// not one of the mapped sentinels.
		Expect(store.UpdateCRL(ctx, []byte("not a CRL"))).To(Succeed())

		rec := revoke(serial, `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusServiceUnavailable))
		Expect(rec.Body.String()).NotTo(ContainSubstring(tmpDir),
			"a CA-side message may name storage paths; it must stay in the log")
		Expect(rec.Body.String()).To(ContainSubstring("server log"))
	})

	It("answers 404 for a serial this CA never issued", func() {
		rec := revoke("DEADBEEF", `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusNotFound))
		Expect(rec.Body.String()).To(ContainSubstring("not found in inventory"))
	})

	It("answers 404 for an unknown serial even when force is set", func() {
		rec := revoke("DEADBEEF", `{"desired_state":"revoked","force":true}`)
		Expect(rec.Code).To(Equal(http.StatusNotFound))
	})

	It("answers 400 for a serial that is not hexadecimal", func() {
		rec := revoke("zzz", `{"desired_state":"revoked"}`)
		Expect(rec.Code).To(Equal(http.StatusBadRequest))
		Expect(rec.Body.String()).To(ContainSubstring("hexadecimal"))
	})

	DescribeTable("rejects any desired_state but revoked",
		func(body string) {
			serial := superseded("api-desired-state")

			rec := revoke(serial, body)
			Expect(rec.Code).To(Equal(http.StatusBadRequest))

			// Nothing was revoked: an unrecognised desired_state must never be
			// read as a request to revoke.
			crlRec := httptest.NewRecorder()
			mux.ServeHTTP(crlRec, httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil))
			block, _ := pem.Decode(crlRec.Body.Bytes())
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(crl.RevokedCertificateEntries).To(BeEmpty())
		},
		Entry("signed", `{"desired_state":"signed"}`),
		Entry("absent", `{}`),
		Entry("empty string", `{"desired_state":""}`),
		Entry("misspelt", `{"desired_state":"revoke"}`),
	)

	It("rejects a body that is not JSON", func() {
		serial := superseded("api-bad-body")

		rec := revoke(serial, `not json`)
		Expect(rec.Code).To(Equal(http.StatusBadRequest))
	})
})
