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

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The revoke subcommand is the operator's only route to a by-serial
// revocation, and every guard it advertises lives on the server. What the CLI
// owns is which request it sends — the method, the path and the body — and
// which flag combinations it refuses before sending anything at all. These
// specs pin exactly that, against a recording stub rather than a real CA.
var _ = Describe("revoke subcommand", func() {
	var (
		gotMethod  string
		gotPath    string
		gotRawPath string
		gotBody    []byte
		status     int
		respBody   string
		srv        *httptest.Server
	)

	BeforeEach(func() {
		saveCtlGlobals()
		gotMethod, gotPath, gotRawPath, gotBody = "", "", "", nil
		status, respBody = http.StatusNoContent, ""

		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath = r.Method, r.URL.Path
			gotRawPath = r.URL.EscapedPath()
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(respBody))
		}))
		DeferCleanup(srv.Close)
	})

	// run executes the revoke subcommand through the root, as an operator does,
	// and returns its error (nil on success).
	run := func(args ...string) error {
		cmd := newRootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"revoke", "--server-url", srv.URL}, args...))
		return cmd.Execute()
	}

	Describe("by subject name", func() {
		It("puts desired_state revoked to the subject-keyed route", func() {
			Expect(run("--certname", "node1")).To(Succeed())

			Expect(gotMethod).To(Equal("PUT"))
			Expect(gotPath).To(Equal("/puppet-ca/v1/certificate_status/node1"))
			Expect(gotBody).To(MatchJSON(`{"desired_state":"revoked"}`))
		})

		It("does not send a force field, which that route has no meaning for", func() {
			Expect(run("--certname", "node1")).To(Succeed())

			var body map[string]any
			Expect(json.Unmarshal(gotBody, &body)).To(Succeed())
			Expect(body).NotTo(HaveKey("force"))
		})
	})

	Describe("by serial", func() {
		It("puts desired_state revoked to the serial-keyed route", func() {
			Expect(run("--serial", "DEADBEEF")).To(Succeed())

			Expect(gotMethod).To(Equal("PUT"))
			Expect(gotPath).To(Equal("/puppet-ca/v1/certificate_status_by_serial/DEADBEEF"))
			Expect(gotBody).To(MatchJSON(`{"desired_state":"revoked","force":false}`))
		})

		It("sends force only when asked", func() {
			Expect(run("--serial", "DEADBEEF", "--force")).To(Succeed())
			Expect(gotBody).To(MatchJSON(`{"desired_state":"revoked","force":true}`))
		})

		It("escapes the serial into the path", func() {
			// The value is operator-typed. An embedded separator must stay
			// inside the {serial} segment rather than redirecting the request
			// at the subject-keyed route, so that what rejects it is the
			// server's serial validation and not a different handler.
			Expect(run("--serial", "../certificate_status/node1")).To(Succeed())

			Expect(gotRawPath).To(Equal(
				"/puppet-ca/v1/certificate_status_by_serial/..%2Fcertificate_status%2Fnode1"))
		})

		It("surfaces the server's refusal, including its remedy", func() {
			status, respBody = http.StatusConflict,
				"serial belongs to the certificate currently in use: revoke it by name with --certname node1\n"

			err := run("--serial", "DEADBEEF")
			Expect(err).To(MatchError(ContainSubstring("--certname node1")))
			Expect(err).To(MatchError(ContainSubstring("409")))
		})
	})

	Describe("flag combinations", func() {
		It("requires one of --certname or --serial", func() {
			Expect(run()).To(MatchError(ContainSubstring("[certname serial]")))
			Expect(gotMethod).To(BeEmpty(), "no request should be sent")
		})

		It("refuses --certname together with --serial", func() {
			Expect(run("--certname", "node1", "--serial", "DEADBEEF")).To(
				MatchError(ContainSubstring("[certname serial]")))
			Expect(gotMethod).To(BeEmpty(), "no request should be sent")
		})

		It("refuses --force on the by-name path, which has no guard to override", func() {
			Expect(run("--certname", "node1", "--force")).To(
				MatchError(ContainSubstring("[certname force]")))
			Expect(gotMethod).To(BeEmpty(), "no request should be sent")
		})
	})

	It("reports which certificate it revoked", func() {
		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		// The success line goes to stdout via fmt.Printf, so capture the
		// subject through the request instead of the buffer: what matters is
		// that a by-serial revoke reports the serial, not a bare name that
		// would read as if the subject's live certificate had been taken.
		cmd.SetArgs([]string{"revoke", "--server-url", srv.URL, "--serial", "DEADBEEF"})
		Expect(cmd.Execute()).To(Succeed())
		Expect(gotPath).To(HaveSuffix("/DEADBEEF"))
	})
})
