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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: pins the %q on import-cert's summary lines.
//
// The subject printed here is decoded from the server's response body and
// nothing re-validates it on the way out, so a compromised or hostile CA can
// choose it freely. These lines go to a terminal through fmt.Printf, which
// escapes nothing, and .github/codeql/codeql-config.yml names this call site
// as one the go/log-injection exclusion's security property rests on. Neither
// guard that file lists reaches it: the depguard rule restricts which logging
// packages may be imported and cannot see a printf verb, and
// cmd/openvox-ca/main_test.go pins slog's handlers, which are not involved.
// Without this spec a revert of %q to %s would pass lint and the whole suite.
var _ = Describe("import-cert output escaping", func() {
	var (
		srv      *httptest.Server
		respBody string
		cfg      string
		certFile string
	)

	// A subject a hostile server could return: both terminators, and a tail
	// shaped to look like a second, reassuring line of CLI output.
	const forged = "evil\r\nImported \"node1\" (serial 01, valid then to later)"

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")

		certFile = filepath.Join(GinkgoT().TempDir(), "cert.pem")
		Expect(os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"), 0o600)).
			To(Succeed())

		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(respBody))
		}))
		DeferCleanup(srv.Close)
	})

	// runCapturingStdout drives import-cert against the stub and returns what
	// it printed. fmt.Printf resolves os.Stdout at call time, so swapping a
	// pipe in around Execute is enough to read back what an operator sees.
	runCapturingStdout := func() string {
		GinkgoHelper()
		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _, _ = r.Close(), w.Close() })

		origStdout := os.Stdout
		defer func() { os.Stdout = origStdout }()
		os.Stdout = w

		cmd := newRootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{
			"import-cert", "--config", cfg, "--server-url", srv.URL,
			"--certname", "node1", "--cert-file", certFile,
		})
		execErr := cmd.Execute()

		os.Stdout = origStdout
		Expect(w.Close()).To(Succeed())
		out, readErr := io.ReadAll(r)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(r.Close()).To(Succeed())
		Expect(execErr).NotTo(HaveOccurred(), "import-cert")
		return string(out)
	}

	DescribeTable("renders a server-chosen subject quoted, so it cannot forge a line",
		func(body string) {
			respBody = body
			out := runCapturingStdout()

			// The consequence a terminator would buy, asserted first so a
			// revert to %s fails for the reason this spec is named for.
			Expect(strings.Count(out, "\n")).To(Equal(1),
				"import-cert prints one summary line; a second means the subject's "+
					"newline reached the terminal unescaped:\n%s", out)
			Expect(out).NotTo(ContainSubstring("\r"),
				"a bare carriage return rewrites the line on an operator's terminal:\n%s", out)

			// Non-vacuity, last: the assertions above hold trivially for a run
			// that printed nothing at all.
			Expect(out).To(ContainSubstring(strconv.Quote(forged)),
				"the server-supplied subject must reach the summary, quoted")
		},
		Entry("on the imported branch", fmt.Sprintf(
			`{"subject":%s,"serial":"0A","not_before":"a","not_after":"b","imported":true}`,
			strconv.Quote(forged))),
		Entry("on the already-tracked branch", fmt.Sprintf(
			`{"subject":%s,"serial":"0A","not_before":"a","not_after":"b","imported":false}`,
			strconv.Quote(forged))),
	)
})
