# Operator CLI (`openvox-ca-ctl`)

`openvox-ca-ctl` mirrors the `puppet cert` / `puppetserver ca` subcommands and communicates with a running `openvox-ca` server over HTTP(S). The `setup`, `import` and `migrate` subcommands operate directly on storage and need no running server.

## Global flags

```text
--config       ""                       Path to YAML config file (auto-detected at /etc/puppet-ca/ctl.yaml)
--server-url   https://localhost:8140   openvox-ca server URL
--ca-cert      ""                       CA cert PEM for TLS verification (omit to use system trust store)
--client-cert  ""                       Client certificate PEM for mTLS
--client-key   ""                       Client private key PEM for mTLS
--insecure                              Skip TLS server certificate verification (vulnerable to MITM; use only for testing)
--verbose, -v                           Enable debug logging
```

Global flags may be placed before or after the subcommand name.

`--ca-cert` takes precedence over `--insecure`: if both are given, the server
certificate is still verified, against the supplied CA certificate, and a `NOTE:`
on stderr says `--insecure` was ignored. To override a `ca_cert` set in the config
file or environment and reach `--insecure`, pass an empty `--ca-cert=""`
alongside it.

The file *replaces* the system trust store rather than adding to it, so a server
whose certificate chains to a public CA stops verifying once `--ca-cert` is
given. It may hold a bundle: every certificate in it that parses is loaded, so a
root plus its intermediates can be passed as one file. A file holding no usable
certificate (a DER export, a truncated download, the wrong file) is rejected
before the connection is attempted rather than failing later in the handshake.

`--client-cert` and `--client-key` must be supplied together; giving only one is
an error.

Subcommands that contact the server write at most one advisory line to
**stderr**, not stdout: a `WARNING:` about MITM exposure when `--insecure` is in
effect, a `NOTE:` when no `--ca-cert` is supplied, the override `NOTE:` above when
both are, and nothing at all when only `--ca-cert` is. These are expected output,
not failures. `setup`, `import` and `migrate` build no client, so they write no
advisory line and never check `--ca-cert`.

`openvox-ca-ctl --version` prints the version (including commit metadata when
built from a git checkout) and exits. Unlike the global flags above,
`--version` is accepted only on the root command, not after a subcommand.

## Configuration

All global flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

The config file is located by checking, in order:

1. `--config /path/to/ctl.yaml` (explicit flag)
2. `PUPPET_CA_CTL_CONFIG` environment variable
3. `/etc/puppet-ca/ctl.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/ctl.yaml`:**

```yaml
server_url:  https://openvox-ca.example.com:8140
ca_cert:     /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
client_cert: /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem
client_key:  /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem
insecure:    false
verbose:     false
```

**Environment variables:**

| Flag | Environment variable |
| --- | --- |
| `--server-url` | `PUPPET_CA_CTL_SERVER_URL` |
| `--ca-cert` | `PUPPET_CA_CTL_CA_CERT` |
| `--client-cert` | `PUPPET_CA_CTL_CLIENT_CERT` |
| `--client-key` | `PUPPET_CA_CTL_CLIENT_KEY` |
| `--insecure` | `PUPPET_CA_CTL_INSECURE` |
| `--verbose` | `PUPPET_CA_CTL_VERBOSE` |

## Subcommands

```bash
# List pending CSRs
openvox-ca-ctl list

# List all certificates (signed, revoked, requested)
openvox-ca-ctl list --all

# Sign a pending CSR
openvox-ca-ctl sign --certname agent.example.com

# Sign all pending CSRs
openvox-ca-ctl sign --all

# Revoke a certificate
openvox-ca-ctl revoke --certname agent.example.com

# Revoke + delete cert and CSR. The delete happens even if the revocation
# fails, so check the server log: a certificate that could not be revoked
# stays a valid credential until it expires, and it is no longer in storage
# to clean again. See docs/api.md for the state that causes it.
openvox-ca-ctl clean --certname agent.example.com

# Re-sign the CRL with a fresh validity window (preserves all revocations)
openvox-ca-ctl reissue-crl

# Generate a server-side key+cert pair (key saved to ./agent.example.com_key.pem)
openvox-ca-ctl generate --certname agent.example.com
openvox-ca-ctl generate --certname agent.example.com --dns alt.example.com --out-dir /etc/ssl

# Import a certificate issued outside this CA's normal flow (e.g. migrated
# from a legacy CA sharing this CA's key)
openvox-ca-ctl import-cert --certname legacy-node.example.com --cert-file legacy-node_cert.pem

# Bootstrap a new CA offline (no server required)
openvox-ca-ctl setup --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com

# Import an external CA cert/key offline
openvox-ca-ctl import \
  --cadir      /etc/puppetlabs/puppet/ssl \
  --cert-bundle ca_cert.pem \
  --private-key ca_key.pem \
  --crl-chain   ca_crl.pem     # optional; omitting it leaves the stored CRL
                               # chain alone. One is generated if none is
                               # stored, and the import is refused if nothing
                               # stored was signed by the certificate being
                               # imported -- pass --crl-chain to replace it.
                               # --crl-chain may hold several concatenated
                               # CRLs in any order. This CA's own is identified
                               # by signature and moved to the front; the rest
                               # are kept and served so agents can do full-chain
                               # revocation checking. Every X509 CRL block must
                               # parse; other PEM block types are ignored and
                               # not stored.

# Migrate an entire CA between storage backends offline (any pair of backends:
# filesystem, sqlite, postgres, mysql, etcd, redis/valkey). Each backend is
# described by a normal openvox-ca config file. Refuses a non-empty destination
# unless --force.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/filesystem.yaml \
  --dest-config   /etc/puppet-ca/postgres.yaml
```

`setup`, `import` and `migrate` operate directly on storage. No running server is needed.
See [storage backends](storage-backends.md#migrating-between-backends) for migration details.

## Offline subcommands on the server binary

Two subcommands live on `openvox-ca` rather than `openvox-ca-ctl`, because they
must reach the storage backend and CA key provider named in the *server's*
configuration. `openvox-ca-ctl` reads a different configuration file and can
only address a local filesystem directory, so it cannot serve a CA whose state
is in PostgreSQL or whose key is in OpenBao Transit.

Neither needs a running server.

```bash
# Emit a certificate signing request for the CA's own key, for an external
# parent CA to sign. Works for every ca_key_provider.
openvox-ca csr --out ca-request.pem

# ... and create the key first, if it does not exist yet
openvox-ca csr --hostname puppet.example.com --create-key --out ca-request.pem

# Install the chain the parent signed, completing the round trip
openvox-ca import-ca-cert --cert-bundle signed-chain.pem
```

`csr` reuses an existing CA certificate's subject verbatim, so re-keying
reproduces the established distinguished name exactly. When no certificate
exists yet it builds the name from `hostname` and the `ca_subject_*` settings —
the same name a self-signed bootstrap would use — and refuses if `hostname` is
unset rather than guessing, because the request is about to be signed by a third
party.

`import-ca-cert` requires a **complete chain, nearest first**: this CA's own
certificate, each issuer after it, ending with a self-signed root. It never
reads the private key; instead it proves the certificate binds the key the
configured provider holds, which is what makes importing without a key file
safe. Use `--force` to replace an existing CA certificate — it re-signs the
stored CRL, which the replacement would otherwise invalidate.

When the CA certificate is mounted read-only from outside (`ca_cert_file`
pointing at a Kubernetes Secret, say), `--out` validates the bundle and writes
it to a file instead of to storage, for loading into the Secret out of band.

See [running under an external root CA](openbao-transit.md#running-under-an-external-root-ca)
for the end-to-end procedure.
