# Configuring the server

This is the full configuration reference for the `openvox-ca` server. For the
operator CLI, see [operator CLI (`openvox-ca-ctl`)](operator-cli.md), which also
covers the offline subcommands that run on the `openvox-ca` binary itself
against this configuration — `csr` and `import-ca-cert`, for running under an
external root CA with any `ca_key_provider`, and `generate`, for minting a
certificate with no running server.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | `""` | Path to YAML config file (auto-detected at `/etc/puppet-ca/config.yaml`) |
| `--cadir` | `""` | CA storage directory (keys, certs, CSRs, CRL); required via flag, env, or config |
| `--host` | `0.0.0.0` | Listen address |
| `--port` | `8140` | Listen port |
| `--hostname` | `""` | CN suffix for a bootstrapped CA (`Puppet CA: <hostname>`); defaults to `puppet` when empty |
| `--autosign-config` | `""` | Autosign mode: `true`, `false`, or path to a file/executable |
| `--tls-cert` | `""` | Server TLS certificate PEM (enables HTTPS when set with `--tls-key`) |
| `--tls-key` | `""` | Server TLS private key PEM |
| `--puppet-server` | `""` | Comma-separated CNs granted admin API access (mTLS only) |
| `--puppet-server-file` | `""` | Path to a file of CNs granted admin API access (one per line; `#` comments and blank lines ignored) |
| `--no-pp-cli-auth` | `false` | Disable `pp_cli_auth` extension as an admin credential; require CN allow list only |
| `--no-tls-required` | `false` | Allow plain HTTP on non-loopback addresses; use only behind a trusted TLS proxy or in test environments |
| `--allow-public-status` | `false` | Allow unauthenticated `GET /certificate_status`; by default this endpoint is admin-only, matching Puppet Server's shipped `auth.conf` |
| `--ocsp-url` | `""` | OCSP responder URL to embed in issued certificates |
| `--crl-url` | `""` | CRL distribution point URL to embed in issued certificates |
| `--metrics-listen` | `""` | Address for the Prometheus exporter (e.g. `127.0.0.1:9140`); empty disables it. See [metrics & monitoring](metrics.md) |
| `--encrypt-ca-key` | `false` | Encrypt the CA private key at rest (AES-256-GCM + Argon2id). See [CA key security](ca-key-security.md) |
| `--ca-key-passphrase-file` | `""` | Path to file containing the CA key passphrase (first line used) |
| `--csr-rate-limit` | `60` | Max CSR submissions per IP per minute on the public `PUT /certificate_request` endpoint (0 disables) |
| `--single-process` | `false` | Disable CA key isolation (run signer and frontend in a single process) |
| `--storage-backend` | `filesystem` | Storage backend for CA state: `filesystem`, `sqlite`, `postgres`, `mysql`, `etcd`, or `redis`. See [storage backends](storage-backends.md) |
| `--etcd-endpoints` | `""` | Comma-separated etcd endpoints (used when `--storage-backend etcd`) |
| `--etcd-key-prefix` | `/puppet-ca` | etcd key namespace for this CA |
| `--ca-cert-file` | `""` | Keep the CA certificate at this local path regardless of backend |
| `--ca-key-file` | `""` | Keep the CA private key at this local path regardless of backend |
| `--ca-key-provider` | `file` | CA private key custody: `file` (default) or `openbao` (OpenBao Transit key). See [OpenBao Transit-engine CA key](openbao-transit.md) for the full `--openbao-*` flag reference |
| `--daemon` | `false` | Fork to background (not recommended in containers; incompatible with the `Type=notify` systemd unit — see [running under systemd](systemd.md)) |
| `--logfile` | `""` | Write JSON logs to this file instead of stderr |
| `--verbosity` / `-v` | `0` | Verbosity: `0`=Info, `1`=Debug, `2`=Trace |
| `--version` | | Print the version and exit; includes commit metadata when built from a git checkout |

## Precedence

All flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

Key generation and CA subject options are intentionally **not** exposed as CLI flags. They are one-time bootstrap decisions that belong in a config file or environment variable. Use the config file or `PUPPET_CA_CA_KEY_ALGO` / `PUPPET_CA_CA_SUBJECT_*` env vars to set them.

The config file is located by checking, in order:

1. `--config /path/to/config.yaml` (explicit flag)
2. `PUPPET_CA_CONFIG` environment variable
3. `/etc/puppet-ca/config.yaml` (auto-detected if the file exists)

## Config file

**Example `/etc/puppet-ca/config.yaml`:**

```yaml
cadir: /etc/puppetlabs/puppet/ssl/ca
host: 0.0.0.0
port: 8140
hostname: puppet.example.com
# A serving certificate issued by this CA — not the CA's own ca_crt.pem and
# ca_key.pem, which cannot serve TLS. See "Serving certificate" below.
tls_cert: /etc/puppetlabs/puppet/ssl/ca/signed/puppet.example.com.pem
tls_key:  /etc/puppetlabs/puppet/ssl/ca/private/puppet.example.com_key.pem
puppet_server: puppet.example.com
puppet_server_file: ""
no_pp_cli_auth: false
no_tls_required: false
allow_public_status: false  # set true to allow unauthenticated GET /certificate_status
                            # (otherwise admin-only: puppet_server CN or pp_cli_auth)
autosign_config: ""
logfile: ""
verbosity: 0
ocsp_url: ""
crl_url: ""
shutdown_timeout_sec: 0  # graceful HTTP-drain budget on SIGTERM; 0 = built-in default (25s)
# Key generation options (applied only when bootstrapping a new CA or generating leaf certs).
ca_key_algo: ""       # "rsa" (default) or "ecdsa"
ca_key_size: 0        # RSA: 2048/3072/4096 (default 4096); ECDSA: 256/384/521 (default 256)
leaf_key_algo: ""     # "rsa" (default) or "ecdsa"
leaf_key_size: 0      # RSA: 2048/3072/4096 (default 2048); ECDSA: 256/384/521 (default 256)
# CA certificate subject fields (applied only when bootstrapping a new CA).
ca_subject_org: ""
ca_subject_ou: ""
ca_subject_country: ""
ca_subject_locality: ""
ca_subject_province: ""
# Validity and path length.
# ca_* apply only when bootstrapping a new CA.
# leaf_validity_days and crl_validity_days apply on every signing / revocation operation.
ca_path_length: -1    # -1 = unconstrained, 0 = leaf certs only, N = N levels of intermediates
ca_validity_days: 0   # 0 = built-in default (~5 years); positive integer overrides
leaf_validity_days: 0 # 0 = built-in default (~5 years); positive integer overrides
promote_cn_to_san: true # add the CN as a DNS SAN when a CSR carries none (RFC 2818)
crl_validity_days: 0  # 0 = built-in default (30 days); positive integer overrides
csr_rate_limit: 60    # max CSR submissions per IP per minute; 0 = disable rate limiting
# Background CRL refresh keeps the CRL's NextUpdate from lapsing on a low-churn CA.
# Safe to run on every replica (serialised on the shared CRL lock).
disable_crl_refresh: false     # true = never auto-refresh the CRL
crl_refresh_interval_sec: 0    # how often to check; 0 = built-in default (1h)
crl_refresh_before_sec: 0      # re-sign when remaining validity < this; 0 = crl_validity/3
# Background CRL sync reloads the stored CRL into the copy this replica's
# revocation checks read, so a revocation performed on another replica takes
# effect here. Read-only, runs on every replica, and is not covered by
# disable_crl_refresh. See "Revocation across replicas" below.
crl_sync_interval_sec: 0       # how often to reload; 0 = built-in default (60s)
# Background OCSP index sync reloads the inventory into the serial index this
# replica's OCSP responder answers from, so a certificate signed on another
# replica stops being reported as "unknown". Read-only; runs on the shared
# backends only, since nothing else can be writing certificates on filesystem
# or sqlite. See "OCSP status across replicas" below.
ocsp_index_sync_interval_sec: 0  # how often to reload; 0 = built-in default (5m)
# Background expired-certificate cleanup (opt-in). When enabled, a job removes
# certificates that expired more than the retention grace period ago from the
# inventory and the CRL, and deletes their stored signed certificate. Safe to run
# on every replica (serialised on the shared CRL lock).
enable_expired_cert_cleanup: false       # true = run the cleanup job
expired_cert_retention_sec: 0            # grace period after a cert's NotAfter before removal; 0 = built-in default (30d)
expired_cert_cleanup_interval_sec: 0     # how often to run; 0 = built-in default (24h)
# CA key encryption at rest.
encrypt_ca_key: false           # encrypt the CA private key (AES-256-GCM + Argon2id)
ca_key_passphrase_file: ""      # path to passphrase file; auto-generated if omitted
# Date/time format in JSON responses.
puppet_datetime_format: false   # use Puppet CA style "2006-01-02T15:04:05MST" instead of RFC 3339
# Certificate auto-renewal (empty-body POST /certificate_renewal).
revoke_on_auto_renew: true      # false matches OpenVox Server's Clojure CA (no revocation on auto-renewal)
# Delayed supersession. A renewal records the certificate it replaced and a sweep
# revokes it once the overlap window elapses, so both verify in the meantime and
# relying parties can pick up the replacement without a gap. The window is a
# deliberate weakening and it is on by default — read "Delayed supersession"
# below, and set 0 for the earlier behaviour of revoking inside the call.
superseded_cert_revoke_after_sec: -1   # overlap window; 0 = revoke inside the renewal; -1/unset = 24h
superseded_cert_sweep_interval_sec: 0  # how often the sweep runs; 0 = built-in default (15m)
```

## Environment variables

Environment variables mirror the CLI flags:

| Flag | Environment variable |
| --- | --- |
| `--cadir` | `PUPPET_CA_CADIR` |
| `--autosign-config` | `PUPPET_CA_AUTOSIGN_CONFIG` |
| `--host` | `PUPPET_CA_HOST` |
| `--port` | `PUPPET_CA_PORT` |
| `--hostname` | `PUPPET_CA_HOSTNAME` |
| `--verbosity` | `PUPPET_CA_VERBOSITY` |
| `--logfile` | `PUPPET_CA_LOGFILE` |
| `--tls-cert` | `PUPPET_CA_TLS_CERT` |
| `--tls-key` | `PUPPET_CA_TLS_KEY` |
| `--puppet-server` | `PUPPET_CA_PUPPET_SERVER` |
| `--puppet-server-file` | `PUPPET_CA_PUPPET_SERVER_FILE` |
| `--no-pp-cli-auth` | `PUPPET_CA_NO_PP_CLI_AUTH` |
| `--no-tls-required` | `PUPPET_CA_NO_TLS_REQUIRED` |
| `--allow-public-status` | `PUPPET_CA_ALLOW_PUBLIC_STATUS` |
| `--ocsp-url` | `PUPPET_CA_OCSP_URL` |
| `--crl-url` | `PUPPET_CA_CRL_URL` |
| `--metrics-listen` | `PUPPET_CA_METRICS_LISTEN` |
| `--csr-rate-limit` | `PUPPET_CA_CSR_RATE_LIMIT` |
| `--encrypt-ca-key` | `PUPPET_CA_ENCRYPT_CA_KEY` |
| `--ca-key-passphrase-file` | `PUPPET_CA_KEY_PASSPHRASE_FILE` |
| `--storage-backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `--etcd-endpoints` | `PUPPET_CA_ETCD_ENDPOINTS` |
| `--etcd-key-prefix` | `PUPPET_CA_ETCD_KEY_PREFIX` |
| `--ca-cert-file` | `PUPPET_CA_CA_CERT_FILE` |
| `--ca-key-file` | `PUPPET_CA_CA_KEY_FILE` |
| `--ca-key-provider` | `PUPPET_CA_CA_KEY_PROVIDER` |
| `--openbao-addr` | `PUPPET_CA_OPENBAO_ADDR` |
| `--openbao-transit-mount` | `PUPPET_CA_OPENBAO_TRANSIT_MOUNT` |
| `--openbao-key-name` | `PUPPET_CA_OPENBAO_KEY_NAME` |
| `--openbao-auth-method` | `PUPPET_CA_OPENBAO_AUTH_METHOD` |

The full `--openbao-*` flag/environment-variable reference (TLS, AppRole, token-file, and
Kubernetes auth settings) is in [OpenBao Transit-engine CA key](openbao-transit.md#configuration).
Storage-backend environment variables are documented per backend in
[storage backends](storage-backends.md).

The CA key passphrase can also be provided via `PUPPET_CA_KEY_PASSPHRASE` (env var only, no CLI flag to avoid `/proc/cmdline` exposure).

**Config file / env var only, no CLI flag:**

| Config key | Environment variable |
| --- | --- |
| `ca_key_algo` | `PUPPET_CA_CA_KEY_ALGO` |
| `ca_key_size` | `PUPPET_CA_CA_KEY_SIZE` |
| `leaf_key_algo` | `PUPPET_CA_LEAF_KEY_ALGO` |
| `leaf_key_size` | `PUPPET_CA_LEAF_KEY_SIZE` |
| `ca_subject_org` | `PUPPET_CA_CA_SUBJECT_ORG` |
| `ca_subject_ou` | `PUPPET_CA_CA_SUBJECT_OU` |
| `ca_subject_country` | `PUPPET_CA_CA_SUBJECT_COUNTRY` |
| `ca_subject_locality` | `PUPPET_CA_CA_SUBJECT_LOCALITY` |
| `ca_subject_province` | `PUPPET_CA_CA_SUBJECT_PROVINCE` |
| `ca_path_length` | `PUPPET_CA_CA_PATH_LENGTH` |
| `ca_validity_days` | `PUPPET_CA_CA_VALIDITY_DAYS` |
| `leaf_validity_days` | `PUPPET_CA_LEAF_VALIDITY_DAYS` |
| `promote_cn_to_san` | `PUPPET_CA_PROMOTE_CN_TO_SAN` |
| `crl_validity_days` | `PUPPET_CA_CRL_VALIDITY_DAYS` |
| `disable_crl_refresh` | `PUPPET_CA_DISABLE_CRL_REFRESH` |
| `crl_refresh_interval_sec` | `PUPPET_CA_CRL_REFRESH_INTERVAL_SEC` |
| `crl_refresh_before_sec` | `PUPPET_CA_CRL_REFRESH_BEFORE_SEC` |
| `crl_sync_interval_sec` | `PUPPET_CA_CRL_SYNC_INTERVAL_SEC` |
| `ocsp_index_sync_interval_sec` | `PUPPET_CA_OCSP_INDEX_SYNC_INTERVAL_SEC` |
| `enable_expired_cert_cleanup` | `PUPPET_CA_ENABLE_EXPIRED_CERT_CLEANUP` |
| `expired_cert_retention_sec` | `PUPPET_CA_EXPIRED_CERT_RETENTION_SEC` |
| `expired_cert_cleanup_interval_sec` | `PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC` |
| `shutdown_timeout_sec` | `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` |
| `etcd_username` | `PUPPET_CA_ETCD_USERNAME` |
| `etcd_password` | `PUPPET_CA_ETCD_PASSWORD` |
| `etcd_dial_timeout_sec` | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC` |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC` |
| `etcd_tls_ca_file` | `PUPPET_CA_ETCD_TLS_CA_FILE` |
| `etcd_tls_cert_file` | `PUPPET_CA_ETCD_TLS_CERT_FILE` |
| `etcd_tls_key_file` | `PUPPET_CA_ETCD_TLS_KEY_FILE` |
| `puppet_datetime_format` | `PUPPET_CA_PUPPET_DATETIME_FORMAT` |
| `revoke_on_auto_renew` | `PUPPET_CA_REVOKE_ON_AUTO_RENEW` |
| `superseded_cert_revoke_after_sec` | `PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC` |
| `superseded_cert_sweep_interval_sec` | `PUPPET_CA_SUPERSEDED_CERT_SWEEP_INTERVAL_SEC` |

> **Note:** `--daemon` is intentionally excluded from config file and environment
> variable support because `PUPPET_CA_DAEMON` is used internally as the daemon fork
> signal.

Boolean env vars accept any value accepted by `strconv.ParseBool`: `1`, `t`, `true`,
`yes`, `on` (case-insensitive) to enable; `0`, `f`, `false`, `no`, `off` to disable.

## Serving certificate

`tls_cert` and `tls_key` name a **serving certificate issued by this CA**, not
the CA's own `ca_crt.pem` and `ca_key.pem`. The CA certificate exists to sign
other certificates, not to identify a server: its `keyUsage` is
`certSign, cRLSign` — neither of the two bits a TLS server needs — and it has
no `subjectAltName`. Pointed at it, the CA starts, logs `TLS enabled`, and
completes the handshake, and then every client that verifies the certificate
rejects it:

```console
$ openssl s_client -connect puppet.example.com:8140 -CAfile ca_crt.pem -verify_hostname puppet.example.com
verify error:num=26:unsuitable certificate purpose
verify error:num=62:hostname mismatch
```

`hostname` does not repair this. It only names a CA at bootstrap, so on a CA
that already exists it changes nothing at all, and even at bootstrap it sets
the subject and adds no SAN — and clients have matched SANs rather than the
common name for years.

### Issuing one

`generate` needs a running server, so the first serving certificate is issued
against this CA started temporarily on loopback with TLS switched off. Stop the
service first if one is already running on port 8140, then:

```bash
# Your configured cadir. The CA writes the serving key under it, and pointing
# --out-dir at the same place keeps a second copy from being left elsewhere.
# The systemd unit's default is /var/lib/puppet-ca, not the path below.
CADIR=/etc/puppetlabs/puppet/ssl/ca

openvox-ca --tls-cert= --tls-key= --host 127.0.0.1 --port 8140 &
PCA_PID=$!

# Poll rather than sleep: bootstrapping a cold cadir generates an RSA-4096 key
# first, which is not a fixed-length wait on a slow or entropy-starved machine.
# 300s matches the TimeoutStartSec the shipped systemd unit allows for it.
for _ in $(seq 1 300); do
  curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca >/dev/null && break
  sleep 1
done
curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca >/dev/null || {
  echo "the CA did not become ready" >&2; kill $PCA_PID; exit 1; }

openvox-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   puppet.example.com \
  --dns        puppet.example.com \
  --out-dir    "$CADIR/private"

kill $PCA_PID; wait $PCA_PID 2>/dev/null
```

Empty `--tls-cert=` and `--tls-key=` override the config file for this one
start, and switching TLS off is all they do — every other setting stays in
force, which matters more than it looks.

> **Warning:** do not reach for `--config /dev/null` here. It switches TLS off
> too, but it discards `storage_backend`, `sql_dsn` and `ca_key_provider` along
> with everything else. On any backend other than `filesystem` the temporary CA
> then finds nothing under `cadir` and **bootstraps a second CA**, with the same
> subject as the real one and no warning that it has done so. The serving
> certificate would be issued by that impostor, every agent would reject it, and
> a stray signing key would be left in `cadir`.

If you are not using a config file at all, pass `--cadir` (and, on a cold
`cadir`, `--hostname` — it is the CN *suffix* a CA is bootstrapped with, once
and permanently, giving `CN=Puppet CA: <hostname>` and defaulting to `puppet`)
plus whatever storage flags the deployment uses. `--dns` is passed explicitly
so the result does not depend on `promote_cn_to_san`, which promotes the CN to
a SAN and is on by default but can be turned off.

### After it is issued

The CA writes the private key to `<cadir>/private/puppet.example.com_key.pem`
on **every** backend: server-generated per-subject keys always go to local disk
and never to the configured store (see [storage
backends](storage-backends.md)), so a CA on Postgres or etcd still keeps a copy
of its serving key on its own filesystem — worth knowing when deciding what to
back up and what to protect. `openvox-ca-ctl` saves its own copy into
`--out-dir`, which is why the command above points that at the same directory:
it lands on the file the CA just wrote, with the same contents, instead of
leaving a second private key somewhere else. That is also why `CADIR` has to
match the `cadir` the server is actually using — `openvox-ca-ctl` does not
create the directory, and it writes the key only after the certificate has been
issued, so a wrong path fails late and needs `clean --certname` before a retry.
Left at its default, `--out-dir` writes into the current working directory.

Only the certificate depends on the backend. It is printed on stdout, and with
the **filesystem** backend the CA also keeps it at
`<cadir>/signed/puppet.example.com.pem` — so there both paths in the example
config already exist, and `tls_cert`/`tls_key` can be set and the service
started. On any other backend the certificate is in the store rather than on
disk, so capture what `generate` prints, put it somewhere the service can read,
and point `tls_cert` at that before starting.

> **Note:** capture it somewhere other than `<cadir>/signed/`. A shell
> redirection creates the file before the request is made, the CA reads that
> as a certificate already issued for the name, and `generate` fails with
> `certificate already exists` — which is also what a second run for the same
> name gets. Use `openvox-ca-ctl clean --certname` first to reissue.

While TLS is off, the whole admin API is unauthenticated: the authorisation
middleware is only installed when `tls_cert` and `tls_key` are both set. So
`--host 127.0.0.1` is not decoration — treat it as required, and keep the
window short. On an ordinary configuration the server would refuse to serve
plain HTTP off loopback anyway, so forgetting it fails safe. On one carrying
`no_tls_required: true` — the documented setup behind a TLS-terminating proxy —
that refusal is already switched off, and so is the block on handing a private
key over plain HTTP. There, the loopback bind is the only thing standing
between an unauthenticated `POST /generate/<subject>` and every interface on
the host.

[Migrating from Puppet
Server](migrating-from-puppet-server.md#step-7-start-openvox-ca) mints a
serving certificate for the CA at Step 7 as well, in a context where no
configuration file exists yet — so it passes `--cadir` explicitly rather than
relying on one.

The block above assumes a shell that owns the CA process, which is not how the
two production deployments in these docs work:

- Under [systemd](systemd.md) the unit is already bound to 8140, so stop it
  first. It also runs as a dedicated user, so run both commands as that user
  rather than under plain `sudo` — `sudo -u puppet-ca openvox-ca --tls-cert=
  ...`. Anything created as `root` is left behind for a service that is not
  root: directories most of all, since they are created `0750` and the service
  then cannot write in them at all, and the private key, which is written
  directly at `0600` and would simply be unreadable. Note that running the CA
  by hand this way gets none of the unit's hardening — including the `LimitCORE=0`
  that keeps a crash from writing the decrypted CA key into a core dump — so
  keep it to the length of this procedure.
- Under Kubernetes it does not apply: the chart takes the serving certificate
  from a Secret — see [Helm chart](helm-chart.md).

### When the certificate cannot serve

A serving certificate is not checked by the TLS stack that presents it, so a
wrong one is silent on this side and fatal on the other. The server therefore
inspects the keypair itself, at startup and on every reload, and warns rather
than refusing — a CA that will not start is worse than one agents distrust,
since the CRL and the public endpoints keep working either way:

```text
level=WARN msg="The TLS certificate just loaded cannot serve TLS to a client that verifies it; issue a serving certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that" cert=/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem subject="Puppet CA: puppet.example.com" problems="it has no subjectAltName, and clients match the hostname against SANs only; its keyUsage allows neither digitalSignature nor keyEncipherment"
```

A second, separate line covers a certificate that *can* serve TLS but should
not be the one doing it — a CA certificate has a signing key attached, and
serving from it puts that key on the network-facing listener:

```text
level=WARN msg="The TLS certificate just loaded is a CA certificate; serving from it puts a signing key on the network-facing listener. Issue an end-entity certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that" cert=/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem subject="Puppet CA: puppet.example.com"
```

Pointing `tls_cert` at `ca_crt.pem` produces both. Two ways of being rejected
by agents still pass every check here, because neither is visible from the
server: a certificate issued by some other CA, and one whose SANs name a host
other than the one agents dial — the `hostname mismatch` above.

## Revocation across replicas

The CA answers "is this certificate revoked?" from a copy of the CRL it holds in
memory, not from storage — the check is on the hot path of every authenticated
request, and it also backs the OCSP responses this replica signs. The copy is
loaded at startup and rewritten whenever *that* process re-signs the CRL, which
on a single node is the whole story.

On the shared backends (`etcd`, `redis`, `postgres`, `mysql`) it is not: only
the replica that handled the revocation re-signs, so every other
replica would go on accepting the certificate until it happened to re-sign on
its own. `crl_sync_interval_sec` closes that. Each replica re-reads the stored
CRL on the interval and installs it if it has advanced, which makes the interval
the worst-case window in which a revoked certificate still works against a
replica that did not revoke it. The default is 60 seconds.

Three things the window does not cover, all worth knowing before you rely on it:

- **OCSP responses already handed out.** The responder signs each response with
  four hours of validity and clients cache it, so a verifier that asked before
  the revocation can keep treating the certificate as valid for that long. The
  replica drops its own cached responses for a serial whenever it installs a
  CRL revoking it — by any route, not only the sync — but answers already in a
  client's or proxy's cache cannot be recalled. This applies whether or not you
  set `--ocsp-url`: that flag decides whether issued certificates advertise the
  responder, not whether `/ocsp` answers. An `unknown` is treated differently
  and is not subject to this — see
  [OCSP status across replicas](#ocsp-status-across-replicas).
- **Certificates issued to the agent before it was locked out.** Revoking one
  serial does not revoke another the same subject already holds. Renewal is not
  a way out — `POST /certificate_renewal` re-reads the CRL from storage rather
  than trusting the cached copy, so a revoked certificate is refused there even
  on a replica that has not synced — but if you are locking out a compromised
  node rather than retiring one certificate, check the inventory for other live
  serials for that subject and retire each one with
  `openvox-ca-ctl revoke --serial <hex>` — see
  [revocation by serial](api.md#revocation-by-serial). `openvox-ca-ctl clean` is
  not a substitute: it revokes the most recently issued serial for the subject
  and removes the stored certificate, leaving the subject's other serials valid.
- **A renewal that coincides with a storage read failure.** That re-read is
  best-effort: if it fails, the check falls back to the CRL already in memory
  rather than refusing every renewal in the fleet over a transient backend
  error. Such a renewal is bounded by the ordinary propagation window instead of
  by the read-through check. `puppetca_crl_sync_failures_total` is what tells
  you it happened.

The read is one small blob, takes no cluster lock, and writes nothing, so it
costs the same on every backend and needs no leader. Lengthening the interval
trades that cost against the window; there is no switch to turn it off, and
`disable_crl_refresh` does not — that setting governs whether this deployment
*re-signs* the CRL on a timer, which is a separate question from whether
revocations reach it.

`filesystem` and `sqlite` are single-node, so the sync has nothing to find and
the setting does not matter there.

To confirm propagation, compare `puppetca_crl_cached_number` (per replica)
against `puppetca_crl_number` (from storage) — see
[metrics](metrics.md#watching-revocation-propagate).

Restarting a replica also reloads its CRL. The sync installs only a CRL this CA
signed, picking out the newest such block wherever it sits in the stored chain —
the same selection the startup loader and the re-sign paths make. A stored chain
carrying nothing of ours leaves the replica on the CRL it already holds and
raises `puppetca_crl_sync_failures_total`; startup warns about the same
condition and the re-sign paths refuse it outright. See
[storage backends](storage-backends.md) for how that state is reached and
repaired.

## OCSP status across replicas

The responder answers from a second per-process copy of shared state: an index
of every serial this CA has issued, built from the inventory. A serial the index
does not hold is answered `unknown` — before the CRL is consulted at all — so
the index decides whether the responder will speak about a certificate, and the
CRL decides what it says.

Like the CRL cache, that index was loaded once at startup and afterwards only
recorded this process's own issuances. On the shared backends that meant a
replica answered `unknown` for every certificate one of its peers had signed,
indefinitely: the certificate is valid, the inventory row is in shared storage,
and only a restart made the replica see it. `ocsp_index_sync_interval_sec`
closes that. Each replica re-reads the inventory on the interval and adds what
it does not already hold, so the interval is the worst-case window in which a
newly issued certificate is reported as unrecognised elsewhere in the fleet.
The default is five minutes — longer than the CRL sync's minute because the
inventory is much larger than the CRL and because `unknown` is not fail-open.

What that window does and does not mean:

- **It is not a revocation bypass.** `unknown` is not `good`, and the mTLS
  admission path reads the CRL rather than this index. What the window costs is
  a peer's ability to say `revoked` at all: an index miss answers before the CRL
  lookup, so during it the responder is silent about a certificate's revocation
  rather than wrong about it.
- **Whether a client notices depends on its soft-fail policy.** A verifier that
  treats `unknown` as a failure sees one replica reject a certificate the others
  accept, which is an unpleasant split to diagnose; one that soft-fails sees
  nothing.
- **An `unknown` is not cached anywhere, by anyone.** A `good` or a `revoked`
  is pre-signed and held for four hours, here and in the verifier. An `unknown`
  is not: this replica does not keep one, and the response carries no
  `NextUpdate` and (on the GET form) `Cache-Control: no-store`, so no verifier
  or proxy keeps one either. That is what makes the window above the whole
  story rather than the window plus four hours — an index refresh changes the
  answer on the very next request that reaches this replica.
- **The pass also removes.** A serial another replica's expired-certificate
  cleanup has pruned leaves this index on the next pass, taking its cached
  response with it, so `puppetca_ocsp_index_serials` tracks the inventory
  downward as well as upward.
- **`filesystem` and `sqlite` are single-node**, so the job has nothing to find
  there; it costs one local inventory read per interval.

The read takes no cluster lock and does not re-sign anything, but it is not
free: it is the whole inventory, so unlike the CRL sync its cost grows with the
number of certificates ever issued — one read of the whole thing, as a blob or
as a row fetch depending on how the backend stores it, plus the small integrity
value either way. That is what the five-minute default is buying
back. Lengthening the interval trades cost against the window; there is no
switch to turn it off, for the same reason the CRL sync has none — a deployment
cannot opt out of `/ocsp` answering, so it should not be able to opt out of
answering correctly.

Note what the cost scales with: certificates **ever issued**, not certificates
currently valid, because the inventory keeps a row per issuance for the life of
the CA. On a long-lived or high-churn fleet that grows without bound, and the
knob that bounds it is `enable_expired_cert_cleanup`, which is off by default —
it prunes rows for certificates that expired more than
`expired_cert_retention_sec` ago, and so caps what this job (and the startup
index build) has to read. Worth turning on before the inventory is large rather
than after.

Watch `puppetca_ocsp_index_serials` across replicas to confirm they agree, and
`puppetca_ocsp_index_sync_failures_total` for a replica that cannot catch up. A
replica reading *above* its peers is not a fault: a pass that overlaps a local
issuance defers its removals to the next one, so a busy replica can hold pruned
serials a little longer.

## Delayed supersession

A renewal replaces a certificate. What happens to the one it replaced is
`superseded_cert_revoke_after_sec`, and the default is **24 hours**: the
predecessor is recorded and stays valid for that long, and a sweep revokes it
once the window elapses. Both certificates verify in the meantime.

The window exists because a certificate other parties are actively verifying
cannot be replaced without a gap unless the predecessor outlives the moment the
replacement is published — the verifiers do not all learn about it at once. An
agent renewing its own credential does not need it: it holds both and simply
stops presenting the old one. The default is set for the harder case.

24 hours is chosen to comfortably exceed the interval on which a fleet notices a
renewal, while staying short enough that a replaced credential is not a standing
one. The same window is what the CA's own serving-certificate work settled on
for the same question asked about a different subject; that work is not in this
release, so there is no companion setting to compare against yet.

> **Upgrading.** This changes behaviour without any config change. Before this
> setting existed, every renewal revoked its predecessor before returning; now
> the predecessor stays valid for 24 hours by default. If you need the old
> behaviour — because your threat model does not tolerate a replaced credential
> outliving its replacement at all — set `superseded_cert_revoke_after_sec: 0`,
> which is an explicit choice and not the same as leaving it unset. You will
> also see a new `superseded.json` in the cadir, a
> `Starting superseded-certificate revocation sweep` line in the logs at
> startup, and `puppetca_supersede_pending` rising and falling.

**The window is a deliberate weakening, and because it is the default it is one
you inherit rather than choose.** For its whole length the replaced certificate
is still a credential this CA accepts, and on the CSR-body (re-key) renewal path
the replaced *private key* is too, since that path issues against a new key and
the old one keeps working until its certificate is revoked. Everything a
compromised predecessor could do, it can still do until the sweep catches up.

Two things bound that, and they are why the default is defensible:

- **A superseded certificate cannot renew itself.** The renewal paths check the
  pending list as well as the CRL, so the credential the window keeps alive
  cannot mint a fresh full-lifetime successor and leave the window behind. That
  check is what makes the window bound the exposure rather than end it, and it
  runs for every deployment because the window now does.
- **Revoking the subject retires it.** `revoke --certname` reaches a recorded
  predecessor in the same call, so containment is not weakened by the window.

If you are replacing a certificate *because* it was compromised, still do not
rely on the window: revoke the serial directly with
`openvox-ca-ctl revoke --serial <hex>`, or set the window to 0 for that
deployment.

Two settings, two questions:

| Setting | Question |
| --- | --- |
| `revoke_on_auto_renew` | *Whether* an auto-renewal retires its predecessor at all. `false` keeps it valid until it naturally expires and records nothing. |
| `superseded_cert_revoke_after_sec` | *When*, on both renewal paths. `0` means inside the renewal call; unset means 24 hours later. |

They compose as you would expect: with `revoke_on_auto_renew: false` the
auto-renewal path records nothing, whatever the delay says, and the CSR-body
path — which always retires what it replaces — still honours the delay.

Some things worth knowing before you rely on it:

- **Each entry keeps the window it was given.** The due time is fixed when the
  supersession is recorded. Shortening the setting later changes what future
  renewals record; it does not retroactively expire a window a fleet may be
  mid-way through relying on, and lengthening it does not extend one.
- **The sweep runs whatever the setting says, including zero.** It is the only
  thing that drains the list, so gating it on the delay would strand every entry
  recorded under an earlier configuration — including one recorded before an
  operator set the window to 0. On a CA that has never recorded a supersession
  each pass is a single absent-key read taking no cluster lock: the sweep rules
  the work out before acquiring one.
- **Each due entry costs one CRL re-sign, under the shared CRL lock.** The sweep
  revokes entries one at a time, and every revocation is a full read, re-sign
  and write of the CRL. A large backlog coming due at once — after a fleet-wide
  outage, say — therefore drains at a rate set by CRL re-sign cost rather than
  by the sweep interval, and it holds the lock that every revocation on every
  replica needs while it does. A pass stops before its budget is spent and logs
  what it deferred to the next one, so a backlog that is not draining is visible
  rather than silent: a deferred pass raises `puppetca_supersede_failures_total`
  and logs `ran out of budget; deferring the rest`, and the entries it defers
  stay on the list. Batching those re-signs into one is a separate change.
- **Revoking a subject retires its pending predecessor too.** `revoke --certname`
  and `DELETE /certificate_status` retire the subject's current certificate
  *and* anything of that subject's still inside its window, in the same call —
  otherwise containing a compromised node would leave a second working
  credential for it in circulation. A predecessor whose supersession was never
  recorded is not reachable that way; see the failure counter below.
- **A superseded certificate cannot renew itself.** It is absent from the CRL
  for the length of its window, so the renewal paths check the pending list as
  well; without that, the credential the window keeps alive could mint a fresh
  full-lifetime successor and leave the window behind. If the list cannot be
  read, renewals are refused rather than admitted — and that check runs whatever
  the window setting says, so a store that cannot serve the
  `superseded` key refuses renewals even on a CA that never enabled one.
- **The sweep interval is added to the window in the worst case.** A certificate
  due at 12:00 is revoked on the first pass after that, so keep
  `superseded_cert_sweep_interval_sec` (15 minutes by default) well below the
  window. The server warns at startup when it is not shorter than the window,
  naming the worst-case effective window — with the default interval, any window
  of 15 minutes or less trips it.
- **Safe on every replica.** The list rewrite and the revocations it drives run
  under the shared cluster CRL lock, so only the first replica to take it
  revokes and the others find the list already drained. No leader election.
- **Watch `puppetca_supersede_pending`** for how many certificates are inside
  their window right now, and `puppetca_supersede_failures_total` for
  supersessions that were lost or could not be carried out — see
  [metrics](metrics.md#delayed-supersession). A pending count that does not fall
  means the sweep is not completing.

## Autosigning

The `--autosign-config` flag controls automatic CSR signing:

| Value | Behaviour |
| --- | --- |
| `false` / `""` | Manual signing only (default) |
| `true` | Sign every incoming CSR immediately |
| `/path/to/file` (not executable) | Glob-pattern allowlist (one pattern per line, `#` comments ignored) |
| `/path/to/script` (executable) | Custom plugin: called with `argv[1]=CN`, CSR PEM on stdin; exit 0 = sign, non-zero = hold |

Allowlist example:

```text
# autosign.conf
*.agent.example.com
compile-*.internal
```

Executable plugin example:

```bash
#!/bin/bash
subject="$1"
csr_pem=$(cat)
# approve only nodes whose name starts with "web-"
[[ "$subject" == web-* ]] && exit 0 || exit 1
```

## Directory layout (filesystem backend)

```text
<cadir>/
  ca_crt.pem          CA certificate
  ca_pub.pem          CA public key
  ca_crl.pem          Certificate Revocation List
  inventory.txt       Signed certificate log (hex serial, dates, subject per line)
  superseded.json     Certificates awaiting delayed revocation (mode 0600; absent until
                      the first supersession) — see "Delayed supersession" above
  signed/             Issued certificates
  requests/           Pending CSRs
  locks/              Same-host lock files (empty, mode 0600) — see below
  private/
    ca_key.pem              CA private key (mode 0600; encrypted PEM when --encrypt-ca-key)
    .ca_key_passphrase      Auto-generated passphrase file (mode 0600; only when --encrypt-ca-key
                            is used without an explicit passphrase source)
    {subject}_key.pem       Server-side generated private keys (mode 0600)
```

> **Note:** Serial numbers are cryptographically random (128-bit). The `serial`
> file used by older Puppet CAs for sequential serial tracking is no longer
> written or read by this server.

The full on-disk layout, including the inventory HMAC files, is documented in
[storage backends](storage-backends.md#filesystem-backend-default). Other backends
store the same logical state elsewhere.

### File permissions

| Content | Mode |
| --- | --- |
| Directories | `0750` |
| Private keys | `0600` |
| CRL file | `0600` |
| Pending-supersession list | `0600` |
| Lock files under `locks/` | `0600` |
| Public data (certs, CSRs, inventory) | `0644` |

The user running `openvox-ca` must own (or have write access to) `--cadir` —
and so must anything else that touches the store. `openvox-ca-ctl` and the
offline `openvox-ca` subcommands take the same locks the server does, so run
them as that user rather than under `sudo`: a root-owned lock file left in
`locks/` will fail the server's next acquisition of that name. See [running a
second process against a live
store](storage-backends.md#running-a-second-process-against-a-live-store).

## Graceful shutdown

On `SIGTERM` or `SIGINT`, the frontend HTTP server calls `http.Server.Shutdown()` with a drain context (wired via `signal.NotifyContext`) so in-flight requests (signing, CRL, OCSP) drain cleanly before the process exits. The request context is cancelled on signal, and the command returns normally rather than calling `os.Exit` on its error paths, so deferred storage and signer cleanup always runs after all connections are done.

The drain budget defaults to **25 seconds** and is configurable via `shutdown_timeout_sec` (config file) or `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` (environment); a non-positive value falls back to the default.

In the default isolated-process deployment, the supervisor gives its child processes the drain budget **plus a 3-second headroom** (28 seconds by default) before force-killing anything that has not exited, so the drain is never truncated.

This is particularly important for **Kubernetes rolling updates**: pods receive `SIGTERM` with a configurable grace period (`terminationGracePeriodSeconds`, default 30 seconds). The defaults (25s drain, 28s supervisor) nest under that 30-second grace so the server drains and exits cleanly before the platform `SIGKILL`s the pod. If you raise `shutdown_timeout_sec`, raise `terminationGracePeriodSeconds` to at least the drain budget plus 3 seconds. Under systemd, raise `TimeoutStopSec` instead — see [running under systemd](systemd.md).

## Reloading configuration

`SIGHUP` re-reads the two file-backed inputs that can be swapped safely while the server is running:

| Input | Effect |
| --- | --- |
| `--tls-cert` / `--tls-key` | The renewed keypair is served to new TLS handshakes; connections in flight keep the certificate they negotiated with |
| `--puppet-server-file` | The admin allow list is rebuilt from the current file contents, merged with the `--puppet-server` value the process started with, and swapped atomically with respect to in-flight requests |

`--puppet-server` (config key `puppet_server`) itself is frozen at startup: a CN removed from it stays an admin until the server restarts. Reload only re-reads the *file*.

Withdrawing admin access has a second caveat: a certificate carrying the `pp_cli_auth` extension is an admin regardless of the allow list (see [admin credential resolution](api.md#admin-credential-resolution)). Revoke that certificate, or run with `--no-pp-cli-auth`, if the reload is meant to decommission a host.

Everything else — the listen address, the storage backend, CA key custody, CA properties, and which autosign configuration is in use — requires a restart.

Two file-backed inputs are consulted live, with no signal needed at all: the autosign allowlist or executable is read on every CSR, and the OpenBao AppRole `role_id`/`secret_id` files are read on every login (see [OpenBao Transit-engine CA key](openbao-transit.md)). Editing those takes effect on the next request; only the settings naming them are fixed at startup.

A reload that fails (an unreadable keypair, a missing allow-list file) is logged and leaves the previous configuration in place; the server keeps serving. Each input is applied independently, so a broken allow list does not block a certificate rotation.

In the default isolated-process deployment, send `SIGHUP` to the supervisor (the process you started); it forwards the signal to the frontend. Under systemd this is `systemctl reload openvox-ca` — see [running under systemd](systemd.md#reloading).

Under `--daemon` the process you started has already forked and exited, so there is nothing left to signal by job control; find the supervisor with `pgrep -f openvox-ca` (the parent of the two child processes) and send `SIGHUP` to that. Running in the foreground under a service manager avoids the question entirely.
