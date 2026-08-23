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
	"context"
	"errors"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// runK8sExporter is the wiring that connects the CA's CRL-update notifications
// to the exporter's reconcile. It must export once at startup, re-export on
// every CRL update, and return promptly on context cancellation.
var _ = Describe("runK8sExporter", func() {
	It("exports at startup, re-exports on CRL update, and returns on cancel", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		// Count server-side applies (a patch) but let the fake tracker handle
		// them so the objects are still created/updated.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())

		// store (*storage.StorageService) satisfies k8sexport.MaterialSource.
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		// An hour of retry interval keeps the retry timer out of this spec:
		// every apply counted below is attributable to startup or the CRL
		// update, not to a retry firing underneath the assertions.
		go func() {
			runK8sExporter(ctx, c, exporter, time.Hour)
			close(done)
		}()

		// (1) The startup export applies the target.
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">=", 1), "startup export did not apply within 2s")
		startupCount := applies.Load()

		// (2) A CRL update wakes the loop and triggers a re-export.
		Expect(c.ReissueCRL(ctx)).To(Succeed())
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">", startupCount), "CRL update did not trigger a re-export within 2s")

		// (3) Cancelling the context stops the loop.
		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})
	// The retry exists because the CRL-update signal can be weeks away on a
	// quiet CA: without it, one failed cycle leaves every target stale until
	// the CRL next changes. These two specs pin both halves of that — a failed
	// cycle is retried unprompted, and a successful one is not.
	It("retries a failed cycle without waiting for a CRL update", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		// Fail the first two applies, then let the tracker handle the rest. If
		// the loop only woke on CRL updates the count would stop at 1, because
		// nothing revokes anything for the lifetime of this spec.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				if applies.Add(1) <= 2 {
					return true, nil, errors.New("boom")
				}
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter, 20*time.Millisecond)
			close(done)
		}()

		// Startup (fails), retry (fails), retry (succeeds).
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">=", 3), "a failed export cycle was not retried within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})

	It("stops retrying once a cycle succeeds", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter, 20*time.Millisecond)
			close(done)
		}()

		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(Equal(int32(1)), "startup export did not apply within 2s")

		// Many retry intervals pass with nothing failing. A timer that is armed
		// unconditionally rather than only on failure would turn the export
		// into a busy poll of the API server, and would show up here.
		Consistently(applies.Load).WithTimeout(500*time.Millisecond).
			WithPolling(20*time.Millisecond).Should(Equal(int32(1)),
			"a successful export cycle was retried anyway")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})
})
