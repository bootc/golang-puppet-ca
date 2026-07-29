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
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// newImportCACertCmd builds the "import-ca-cert" subcommand, which installs a
// CA certificate chain signed by an external parent — the other half of
// "openvox-ca csr".
//
// It is distinct from "openvox-ca-ctl import", which takes a certificate *and*
// its private key and can only address a local filesystem directory. This one
// takes no key: the key already exists, wherever ca_key_provider says, and the
// command proves the certificate matches it rather than being handed it.
func newImportCACertCmd() *cobra.Command {
	var (
		configFile string
		caDir      string
		bundleFile string
		outFile    string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "import-ca-cert",
		Short: "Install a CA certificate chain signed by an external parent",
		Long: `Install a CA certificate chain signed by an external parent CA, completing the
process started by "openvox-ca csr".

The bundle must be a complete chain, ordered nearest-first: this CA's own
certificate, each issuer after it, ending with a self-signed root. The CA's
private key is not required and is never read — it stays wherever
ca_key_provider puts it — but the command proves the certificate binds that key
before writing anything.

With --out the bundle is validated and written to a file instead of storage,
for deployments where the CA certificate is mounted read-only from outside
(a Kubernetes Secret, for example).`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outFile != "" && force {
				// --force's obligation is to re-sign the stored CRL, which is a
				// storage write --out by definition does not perform. Doing it
				// anyway would move the CRL to the new issuer while the
				// certificate sat in a file the operator had not yet installed,
				// leaving the CA serving a CRL that does not match its own
				// certificate.
				return fmt.Errorf("--out cannot be combined with --force: replacing an in-use CA certificate " +
					"requires re-signing the stored CRL, which --out does not write. Install the validated " +
					"bundle, restart every replica, then run 'openvox-ca-ctl reissue-crl'")
			}

			bundlePEM, err := os.ReadFile(bundleFile)
			if err != nil {
				return fmt.Errorf("reading --cert-bundle: %w", err)
			}

			cfg, err := loadServerConfig(resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml"))
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}

			rt, err := resolveRuntime(cmd.Context(), cfg, true)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()

			myCA := ca.New(rt.Store, ca.AutosignConfig{Mode: "off"}, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}
			myCA.KeyProvider = rt.KeyProvider

			// Validate before touching anything, so --out and a real import
			// apply exactly the same checks.
			certs, err := ca.ParseCABundle(bundlePEM)
			if err != nil {
				return fmt.Errorf("--cert-bundle: %w", err)
			}
			if err := ca.ValidateCABundleOrder(certs); err != nil {
				return fmt.Errorf("--cert-bundle: %w", err)
			}

			signer, err := myCA.LoadOrCreateCAKey(cmd.Context(), false)
			if err != nil {
				if errors.Is(err, ca.ErrKeyProviderKeyNotFound) {
					return fmt.Errorf("no CA key exists to match this certificate against: run "+
						"'openvox-ca csr --create-key' first, or provision the key out of band: %w", err)
				}
				return err
			}

			if outFile != "" {
				return writeValidatedBundle(cmd, outFile, bundlePEM, certs[0].Subject.CommonName)
			}

			hasCert, err := rt.Store.HasCACert(cmd.Context())
			if err != nil {
				return fmt.Errorf("checking for an existing CA certificate: %w", err)
			}
			if hasCert && !force {
				return fmt.Errorf("a CA certificate already exists: refusing to replace it, because every " +
					"certificate issued under the current one stops verifying if the replacement does not " +
					"chain to it. Pass --force if that is intended")
			}

			// --force always re-signs the CRL. The stored one was signed by the
			// key being replaced and names the subject being replaced; whether
			// this import is a re-key, a re-subject or both, nothing can verify
			// it afterwards. Revocation entries are carried across.
			var crlPEM []byte
			if hasCert {
				crlPEM, err = ca.ResignStoredCRL(cmd.Context(), rt.Store, certs[0], signer, myCA.CRLValidityDuration())
				if err != nil {
					return err
				}
			}

			if err := ca.ImportCAMaterial(cmd.Context(), rt.Store, bundlePEM, nil, crlPEM, signer); err != nil {
				return annotateOverlayWriteError(err, cfg)
			}

			_, err = fmt.Fprintf(cmd.ErrOrStderr(),
				"Imported CA certificate %q (%d certificates in chain)\n",
				certs[0].Subject.CommonName, len(certs))
			return err
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "CA storage directory (overrides the config file)")
	f.StringVar(&bundleFile, "cert-bundle", "", "Path to the signed CA certificate chain, nearest first")
	f.StringVar(&outFile, "out", "", "Validate and write the bundle to this file instead of to storage")
	f.BoolVar(&force, "force", false, "Replace an existing CA certificate, re-signing the stored CRL")
	_ = cmd.MarkFlagRequired("cert-bundle")

	return cmd
}

// writeValidatedBundle writes an already-validated bundle to path.
func writeValidatedBundle(cmd *cobra.Command, path string, bundlePEM []byte, cn string) error {
	// G703: path is the operator's own --out argument on an offline command they
	// are running deliberately, and the content is a certificate chain that has
	// already been fully validated. There is no privilege boundary to cross:
	// constraining where an operator may write their own file would add nothing.
	if err := os.WriteFile(path, bundlePEM, storage.FilePermPublic); err != nil { //nolint:gosec // G703: operator-supplied --out path on an offline command
		return fmt.Errorf("writing %s: %w", path, err)
	}
	_, err := fmt.Fprintf(cmd.ErrOrStderr(),
		"Validated CA certificate %q written to %s (not installed; load it into the configured ca_cert_file)\n",
		cn, path)
	return err
}

// annotateOverlayWriteError appends guidance when a write failed and the CA
// certificate is overlaid onto a local path.
//
// The trigger is the configuration, not a filesystem probe: an overlay onto a
// writable path is a supported configuration and must not be pre-emptively
// refused. So the write is attempted, and only its failure is annotated — the
// predicate cannot be wrong about writability because it never guesses.
func annotateOverlayWriteError(err error, cfg *serverConfig) error {
	if err == nil || cfg.CACertFile == "" {
		return err
	}
	return fmt.Errorf("%w\n\nThe CA certificate is overlaid onto %s. If that path is read-only "+
		"(a mounted Kubernetes Secret, for example), re-run with --out to write a validated bundle "+
		"to a file and load it into the Secret out of band", err, cfg.CACertFile)
}
