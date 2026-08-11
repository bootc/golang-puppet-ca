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

package sdnotify_test

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
	"golang.org/x/sys/unix"
)

// fakeManager stands in for the service manager: it owns the datagram socket
// named by $NOTIFY_SOCKET and records every message the Notifier sends.
type fakeManager struct {
	msgs chan string

	mu      sync.Mutex
	conn    *net.UnixConn
	path    string
	stopped bool
}

// stop closes the manager's socket and unlinks it, so a Notifier that
// connected successfully now fails on every write — the "service manager went
// away" case. Idempotent, so the spec and the cleanup can both call it.
func (m *fakeManager) stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return nil
	}
	m.stopped = true
	err := m.conn.Close()
	os.Remove(m.path)
	return err
}

// newFakeManager binds a datagram socket in a temporary directory, points
// $NOTIFY_SOCKET at it, and starts draining messages. Both the socket and the
// environment variable are restored when the spec finishes.
func newFakeManager() *fakeManager {
	dir, err := os.MkdirTemp("", "sdnotify")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(os.RemoveAll(dir)).To(Succeed()) })

	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	Expect(err).NotTo(HaveOccurred())

	m := &fakeManager{msgs: make(chan string, 32), conn: conn, path: path}
	DeferCleanup(func() { Expect(m.stop()).To(Succeed()) })
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				close(m.msgs)
				return
			}
			// Never block on the channel: a spec that ignores the messages
			// (the concurrency one sends hundreds) would otherwise park this
			// goroutine on a full buffer, stop draining the socket, and leak
			// it — while the sender blocks on a full receive queue.
			select {
			case m.msgs <- string(buf[:n]):
			default:
			}
		}
	}()

	setEnv("NOTIFY_SOCKET", path)
	return m
}

// next returns the next message received, failing the spec if none arrives.
func (m *fakeManager) next() string {
	var msg string
	EventuallyWithOffset(1, m.msgs).Should(Receive(&msg))
	return msg
}

// setEnv sets an environment variable for the duration of the current spec,
// restoring the previous value (or absence) afterwards. Ginkgo nodes cannot
// use testing.T.Setenv, and specs must not leak state into their siblings.
func setEnv(key, value string) {
	prev, had := os.LookupEnv(key)
	ExpectWithOffset(1, os.Setenv(key, value)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, prev)).To(Succeed())
			return
		}
		Expect(os.Unsetenv(key)).To(Succeed())
	})
}

// unsetEnv removes an environment variable for the duration of the spec.
func unsetEnv(key string) {
	prev, had := os.LookupEnv(key)
	ExpectWithOffset(1, os.Unsetenv(key)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, prev)).To(Succeed())
		}
	})
}

var _ = Describe("Notifier", func() {
	BeforeEach(func() {
		// Every spec starts from a known environment: specs that want a
		// service manager or a watchdog opt in explicitly.
		unsetEnv("NOTIFY_SOCKET")
		unsetEnv("WATCHDOG_USEC")
	})

	Context("when NOTIFY_SOCKET is not set", func() {
		It("is inert and safe to use", func() {
			n := sdnotify.New()
			Expect(n.Enabled()).To(BeFalse())
			Expect(n.WatchdogInterval()).To(BeZero())

			// None of these may panic or block; there is nothing to notify.
			n.Ready("serving")
			n.Status("working")
			n.Reloading("reloading")
			n.Stopping("stopping")
			n.Watchdog()
			Expect(n.Close()).To(Succeed())
		})
	})

	Context("when NOTIFY_SOCKET names an unusable socket", func() {
		It("degrades to inert rather than failing", func() {
			setEnv("NOTIFY_SOCKET", filepath.Join(GinkgoT().TempDir(), "does-not-exist.sock"))
			n := sdnotify.New()
			Expect(n.Enabled()).To(BeFalse())
			n.Ready("serving") // must not panic
		})
	})

	Context("when a service manager is listening", func() {
		var (
			mgr *fakeManager
			n   *sdnotify.Notifier
		)

		BeforeEach(func() {
			mgr = newFakeManager()
			n = sdnotify.New()
			Expect(n.Enabled()).To(BeTrue())
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })
		})

		It("reports readiness with a status line", func() {
			n.Ready("Serving HTTPS on 0.0.0.0:8140")
			Expect(mgr.next()).To(Equal("READY=1\nSTATUS=Serving HTTPS on 0.0.0.0:8140\n"))
		})

		It("omits the status line when no status is given", func() {
			n.Ready("")
			Expect(mgr.next()).To(Equal("READY=1\n"))
		})

		It("updates the status text on its own", func() {
			n.Status("Initialising CA")
			Expect(mgr.next()).To(Equal("STATUS=Initialising CA\n"))
		})

		It("sends nothing for an empty status update", func() {
			n.Status("")
			n.Status("second") // a sentinel that must arrive first if the empty one was dropped
			Expect(mgr.next()).To(Equal("STATUS=second\n"))
		})

		It("reports the start of a reload", func() {
			n.Reloading("Reloading TLS material")
			msg := mgr.next()
			Expect(msg).To(HavePrefix("RELOADING=1\n"))
			Expect(msg).To(HaveSuffix("STATUS=Reloading TLS material\n"))
		})

		It("includes a monotonic timestamp with the reload on Linux", func() {
			// Type=notify-reload rejects a RELOADING=1 that carries no
			// MONOTONIC_USEC, so this field is load-bearing on Linux.
			if runtime.GOOS != "linux" {
				Skip("MONOTONIC_USEC is only sent on Linux")
			}
			var before, after unix.Timespec
			Expect(unix.ClockGettime(unix.CLOCK_MONOTONIC, &before)).To(Succeed())
			n.Reloading("")
			Expect(unix.ClockGettime(unix.CLOCK_MONOTONIC, &after)).To(Succeed())

			msg := mgr.next()
			Expect(msg).To(MatchRegexp(`\ARELOADING=1\nMONOTONIC_USEC=[0-9]+\n\z`))

			// Bracket the value: systemd compares this stamp against the
			// moment it sent SIGHUP, so a zero or wrong-magnitude reading
			// makes it treat a genuine acknowledgement as stale.
			field := strings.TrimSuffix(strings.SplitN(msg, "MONOTONIC_USEC=", 2)[1], "\n")
			usec, err := strconv.ParseUint(field, 10, 64)
			Expect(err).NotTo(HaveOccurred())
			Expect(usec).To(BeNumerically(">=", uint64(before.Nano())/uint64(time.Microsecond)))
			Expect(usec).To(BeNumerically("<=", uint64(after.Nano())/uint64(time.Microsecond)))
		})

		It("reports the start of shutdown", func() {
			n.Stopping("Draining connections")
			Expect(mgr.next()).To(Equal("STOPPING=1\nSTATUS=Draining connections\n"))
		})

		It("ignores watchdog keep-alives when the watchdog is disabled", func() {
			n.Watchdog()
			n.Status("sentinel")
			Expect(mgr.next()).To(Equal("STATUS=sentinel\n"))
		})

		It("survives a service manager that has gone away", func() {
			// The failure send's comment leads with: connected at startup,
			// peer gone later. systemd restarting mid-run does this.
			Expect(mgr.stop()).To(Succeed())

			n.Ready("still here")
			n.Status("still here")
			n.Watchdog()

			Expect(n.Enabled()).To(BeTrue(), "a failed write must not disable the notifier")
			Expect(n.Close()).To(Succeed())
		})

		It("is safe to close twice", func() {
			Expect(n.Close()).To(Succeed())
			Expect(n.Close()).To(Succeed())
			n.Status("after close") // must not panic
			Expect(n.Enabled()).To(BeFalse())
		})

		Describe("status sanitisation", func() {
			// SECURITY: status text is built from certificate subjects, which
			// are attacker-influenced. A raw newline would let the remainder be
			// parsed as further protocol assignments.
			It("folds newlines so protocol fields cannot be injected", func() {
				n.Status("evil.example.com\nREADY=1\nMAINPID=1")
				msg := mgr.next()
				Expect(msg).To(Equal("STATUS=evil.example.com READY=1 MAINPID=1\n"))
				Expect(strings.Count(msg, "\n")).To(Equal(1))
			})

			It("folds carriage returns and NUL bytes", func() {
				n.Status("a\rb\x00c")
				Expect(mgr.next()).To(Equal("STATUS=a b c\n"))
			})

			// Ready, Reloading and Stopping carry the same attacker-influenced
			// text through the same statusLine call. They are thin wrappers
			// today, but the SECURITY contract is theirs too, so pin it at
			// each of them rather than only at Status.
			DescribeTable("holds at every method that carries status text",
				func(send func(string), want []string) {
					send("evil.example.com\nREADY=1\nMAINPID=1\x1b[31m")
					msg := mgr.next()

					// The datagram must contain exactly the assignments the
					// method is supposed to send — the injected READY=1 and
					// MAINPID= have to end up inside the STATUS value, not
					// beside it as fields of their own.
					lines := strings.Split(strings.TrimSuffix(msg, "\n"), "\n")
					Expect(lines).To(Equal(want))
					Expect(msg).NotTo(ContainSubstring("\x1b"))
				},
				Entry("Ready", func(v string) { n.Ready(v) },
					[]string{"READY=1", "STATUS=evil.example.com READY=1 MAINPID=1 [31m"}),
				Entry("Status", func(v string) { n.Status(v) },
					[]string{"STATUS=evil.example.com READY=1 MAINPID=1 [31m"}),
				Entry("Stopping", func(v string) { n.Stopping(v) },
					[]string{"STOPPING=1", "STATUS=evil.example.com READY=1 MAINPID=1 [31m"}),
			)

			It("holds for Reloading, which carries an extra field", func() {
				// Reloading emits MONOTONIC_USEC on Linux, so it is the one
				// method whose datagram legitimately has two newlines before
				// the status; assert the status itself is still folded.
				n.Reloading("evil.example.com\nREADY=1\x1b[31m")
				msg := mgr.next()

				Expect(msg).To(HavePrefix("RELOADING=1\n"))
				Expect(msg).To(HaveSuffix("STATUS=evil.example.com READY=1 [31m\n"))
				Expect(msg).NotTo(ContainSubstring("\x1b"))
			})

			It("folds every other control character too", func() {
				// Only the newline can break framing, but the status text is
				// relayed to a terminal by `systemctl status`, so escape
				// sequences should not survive either.
				n.Status("before\x1b[31mred\tafter")
				Expect(mgr.next()).To(Equal("STATUS=before [31mred after\n"))
			})

			DescribeTable("keeps the datagram well-formed for input that is not valid UTF-8",
				func(status string) {
					// Certificate subjects are ASN.1 byte strings with no
					// UTF-8 guarantee, and strings.Map turns each invalid byte
					// into a three-byte replacement rune — which can push an
					// otherwise-short subject past the byte cap.
					n.Status(status)
					msg := mgr.next()

					Expect(strings.Count(msg, "\n")).To(Equal(1), "exactly one assignment")
					Expect(msg).To(HavePrefix("STATUS="))
					value := strings.TrimSuffix(strings.TrimPrefix(msg, "STATUS="), "\n")
					Expect(utf8.ValidString(value)).To(BeTrue())
					Expect(len(value)).To(BeNumerically("<=", 256))
				},
				Entry("a lone continuation byte", "node\x80.example.com"),
				Entry("a truncated sequence", "node\xe2\x82.example.com"),
				Entry("an overlong encoding", "node\xc0\xaf.example.com"),
				Entry("invalid bytes straddling the cap", strings.Repeat("x", 250)+strings.Repeat("\x80", 20)),
				Entry("nothing but invalid bytes", strings.Repeat("\xff", 300)),
			)

			It("truncates an over-long status", func() {
				n.Status(strings.Repeat("x", 500))
				msg := mgr.next()
				Expect(msg).To(Equal("STATUS=" + strings.Repeat("x", 256) + "\n"))
			})

			It("does not split a multi-byte character at the truncation point", func() {
				// The cap counts bytes, so a certificate subject containing an
				// IDN domain or a non-English organisation name can put a rune
				// astride the boundary. Emitting half of it would be invalid
				// UTF-8 in the journal.
				status := strings.Repeat("x", 255) + "\u20ac" + strings.Repeat("y", 10)
				n.Status(status)

				msg := mgr.next()
				value := strings.TrimSuffix(strings.TrimPrefix(msg, "STATUS="), "\n")
				Expect(utf8.ValidString(value)).To(BeTrue(), "truncated status must stay valid UTF-8")
				Expect(value).To(Equal(strings.Repeat("x", 255)), "the straddling rune is dropped, not halved")
			})
		})
	})

	Describe("watchdog configuration", func() {
		var mgr *fakeManager

		BeforeEach(func() {
			mgr = newFakeManager()
		})

		It("adopts the interval published in WATCHDOG_USEC", func() {
			setEnv("WATCHDOG_USEC", "30000000")
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.WatchdogInterval()).To(Equal(30 * time.Second))
			n.Watchdog()
			Expect(mgr.next()).To(Equal("WATCHDOG=1\n"))
		})

		It("keeps feeding the watchdog independently of WATCHDOG_PID", func() {
			// The frontend child, not the unit's main PID, is the process that
			// knows the CA is healthy, so the PID check is deliberately not
			// applied. See watchdogIntervalFromEnv.
			setEnv("WATCHDOG_USEC", "10000000")
			setEnv("WATCHDOG_PID", "1")
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.WatchdogInterval()).To(Equal(10 * time.Second))

			// The deviation from sd_watchdog_enabled(3) is specifically about
			// still sending from a process that is not the main PID, so the
			// datagram is the part worth pinning.
			n.Watchdog()
			Expect(mgr.next()).To(Equal("WATCHDOG=1\n"))
		})

		DescribeTable("rejects an unusable interval",
			func(value string) {
				setEnv("WATCHDOG_USEC", value)
				n := sdnotify.New()
				DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

				Expect(n.WatchdogInterval()).To(BeZero())
				n.Watchdog()
				n.Status("sentinel")
				Expect(mgr.next()).To(Equal("STATUS=sentinel\n"))
			},
			Entry("not a number", "soon"),
			Entry("zero", "0"),
			Entry("negative", "-1"),
			// Would overflow time.Duration's nanoseconds and wrap into a tiny
			// (or negative) interval, causing a keep-alive storm.
			Entry("beyond time.Duration's range", "18446744073709551615"),
		)

		It("accepts the largest interval that still fits time.Duration", func() {
			// Guards the boundary of the overflow check itself: one microsecond
			// more must be rejected, this value must not be.
			const maxUsec = uint64(1<<63-1) / uint64(time.Microsecond)
			setEnv("WATCHDOG_USEC", strconv.FormatUint(maxUsec, 10))
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.WatchdogInterval()).To(Equal(time.Duration(maxUsec) * time.Microsecond))
		})

		It("rejects one microsecond beyond that", func() {
			const maxUsec = uint64(1<<63-1) / uint64(time.Microsecond)
			setEnv("WATCHDOG_USEC", strconv.FormatUint(maxUsec+1, 10))
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.WatchdogInterval()).To(BeZero())
		})
	})

	Describe("an abstract-namespace socket", func() {
		It("connects to a @-prefixed NOTIFY_SOCKET", func() {
			// sd_notify(3) spells abstract sockets with a leading '@'. This
			// proves an @-prefixed NOTIFY_SOCKET connects and round-trips end
			// to end; it cannot single out New's own '@'-to-NUL translation,
			// because Go's syscall layer accepts either spelling. Only Linux
			// has the abstract namespace at all.
			if runtime.GOOS != "linux" {
				Skip("the abstract socket namespace is Linux-only")
			}

			name := "@openvox-ca-sdnotify-test-" + strconv.Itoa(os.Getpid())
			conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { Expect(conn.Close()).To(Succeed()) })

			received := make(chan string, 1)
			go func() {
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				received <- string(buf[:n])
			}()

			setEnv("NOTIFY_SOCKET", name)
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.Enabled()).To(BeTrue())
			n.Ready("abstract")
			Eventually(received).Should(Receive(Equal("READY=1\nSTATUS=abstract\n")))
		})
	})

	Describe("concurrent use", func() {
		It("tolerates notifications racing a close", func() {
			// This is the production shape: the heartbeat and reload goroutines
			// are never joined before the frontend's deferred Close, so both
			// sides of that race have to be synchronised. This spec only fails
			// under -race, which mage test:unit passes (see magefile.go).
			newFakeManager()
			n := sdnotify.New()
			Expect(n.Enabled()).To(BeTrue())

			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					for j := 0; j < 50; j++ {
						n.Status("still here")
						n.Watchdog()
						n.Enabled()
					}
				}()
			}

			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				Expect(n.Close()).To(Succeed())
			}()

			wg.Wait()
			Expect(n.Enabled()).To(BeFalse())
		})
	})

	Describe("a nil Notifier", func() {
		It("behaves like a disabled one", func() {
			var n *sdnotify.Notifier
			Expect(n.Enabled()).To(BeFalse())
			Expect(n.WatchdogInterval()).To(BeZero())
			n.Ready("x")
			n.Status("x")
			n.Reloading("x")
			n.Stopping("x")
			n.Watchdog()
			Expect(n.Close()).To(Succeed())
		})
	})
})
