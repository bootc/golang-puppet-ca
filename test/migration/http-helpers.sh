#!/bin/bash
# HTTP helpers for the migration integration suite.
#
# Sourced by migration-test.sh; also sourced directly by http-helpers-test.sh,
# which is the regression suite for the retry logic below.  Sourcing this file
# must have no side effects beyond defining functions and creating one temp
# directory, so keep executable statements out of it.
#
# Why this file exists (issue #208)
# ---------------------------------
# The suite's pre-flight fetch of the old CA cert failed once in CI and passed
# on a re-run of the same commit.  The old Puppet Server had logged
# `"GET /puppet-ca/v1/certificate/ca HTTP/1.1" 200 3907` three milliseconds
# before the assertion failed, so the response was sent -- but the assertion
# had been written as
#
#     _cert=$(curl -sfk "$URL/..." 2>/dev/null) || true
#     echo "$_cert" | grep -qF "BEGIN CERTIFICATE" && pass ... || fail "..."
#
# `|| true` discarded curl's exit status, `2>/dev/null` discarded its error
# message, and `fail` was called with no diagnostic.  A transfer truncated
# mid-flight (curl exit 18), a TLS handshake failure (35, 60) and a 500 are
# indistinguishable in that output, so the report could not be closed.
#
# These helpers keep all three pieces of evidence.  Nothing about the
# assertions changes: the caller still decides pass/fail from the body it got.
# What changes is that when it fails, it can say why.
#
# The body excerpt in a diagnostic is safe to print here because every
# credential this suite handles is a throwaway CA created for the run.  Do not
# reuse these helpers anywhere a response body could carry a real secret.

# -- Tunables -----------------------------------------------------------------
# Attempts and delay for http_get_retry.  Four attempts two seconds apart give
# the old server six seconds to answer, which is longer than the blind
# `sleep 2` that used to stand in for waiting on its autosign -- and unlike the
# sleep, it costs nothing when the first attempt already works.
: "${HTTP_RETRY_ATTEMPTS:=4}"
: "${HTTP_RETRY_DELAY:=2}"

# Per-request time bounds.  Without these the retry is bounded in attempts but
# not in wall clock: a server that completes the handshake and then stalls
# blocks the first attempt forever, and the retry never reaches its second.
# They are also what makes curl's exit 28 -- documented below as a state this
# reports -- reachable at all.  Generous enough not to fire on a loaded CI
# runner talking to a JVM Puppet Server; the whole point is to catch a stall,
# not a slow response.
: "${HTTP_CONNECT_TIMEOUT:=10}"
: "${HTTP_MAX_TIME:=60}"

# Longest body excerpt to put in a TAP diagnostic.  A PEM is ~2 kB and a TAP
# comment has to stay on one line, so the excerpt is a fingerprint of what
# arrived (enough to tell a PEM header from an HTML error page from nothing),
# not the payload.  The exact byte count is reported separately and is what
# actually distinguishes a truncated transfer from a complete one.
: "${HTTP_DIAG_BODY_CHARS:=120}"

# Scratch space for curl's stderr.  The caller owns removing this: installing
# a trap here would silently replace the suite's own `trap cleanup EXIT`.
_HTTP_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/http-helpers.XXXXXX") || {
    printf 'Bail out! http-helpers.sh: cannot create a scratch directory\n' >&2
    exit 1
}

# -- Results of the last request ----------------------------------------------
# Set by http_get and http_get_retry, for the caller to use in its diagnostic:
#
#   _HTTP_BODY      response body ('' when curl failed before writing one)
#   _HTTP_RC        curl's exit status (0 ok, 18 partial transfer, 7 refused,
#                   35/60 TLS, 28 timeout)
#   _HTTP_CODE      HTTP status code, or '000' when no response line arrived
#   _HTTP_BYTES     length of _HTTP_BODY in bytes
#   _HTTP_ERR       curl's stderr, squashed to one line
#   _HTTP_ATTEMPTS  how many requests were made
#   _HTTP_INFO      all of the above as one TAP-comment-safe line
_HTTP_BODY=''
_HTTP_RC=0
_HTTP_CODE=''
_HTTP_BYTES=0
_HTTP_ERR=''
_HTTP_ATTEMPTS=0
_HTTP_INFO=''

# -- Helper: squash stdin to a single line ------------------------------------
# TAP diagnostics are one line each ("  # text"), so anything embedded in one
# has to lose its newlines or it corrupts the stream for a TAP consumer.
# Used for openssl's output and directory listings as well as curl's, which is
# why it is named for the diagnostic rather than for HTTP.
diag_oneline() {
    tr '\r\n\t' '   ' | sed -e 's/  */ /g' -e 's/^ //' -e 's/ *$//'
}

# -- Helper: render the last request as one diagnostic line -------------------
_http_set_info() {
    local _excerpt
    _excerpt=$(printf '%s' "$_HTTP_BODY" | diag_oneline)
    if [ "${#_excerpt}" -gt "$HTTP_DIAG_BODY_CHARS" ]; then
        _excerpt="${_excerpt:0:$HTTP_DIAG_BODY_CHARS}..."
    fi

    _HTTP_INFO="rc=${_HTTP_RC} http=${_HTTP_CODE} bytes=${_HTTP_BYTES}"
    [ "$_HTTP_ATTEMPTS" -gt 1 ] && \
        _HTTP_INFO="${_HTTP_INFO} attempts=${_HTTP_ATTEMPTS}"
    [ -n "$_HTTP_ERR" ] && _HTTP_INFO="${_HTTP_INFO} curl=[${_HTTP_ERR}]"
    [ -n "$_excerpt" ] && _HTTP_INFO="${_HTTP_INFO} body=[${_excerpt}]"
    return 0
}

# -- Helper: one request, recording everything --------------------------------
_http_do() {  # url [curl-arg...]
    local _url="$1"; shift
    local _errf="${_HTTP_TMPDIR}/curl.err" _out

    # -sS: no progress meter, but keep curl's error message -- which is the
    # evidence #208 needed and could not get -- and capture it rather than
    # sending it to /dev/null.
    #
    # Deliberately no -f: with the status code recorded separately there is
    # nothing left for -f to buy, and without it a 4xx/5xx body survives to be
    # reported instead of being suppressed.  Assertions are unaffected because
    # they all test the body's content, and an error body does not contain
    # "BEGIN CERTIFICATE" either.
    #
    # The \n before %{http_code} is what makes the split below unambiguous for
    # bodies that themselves contain newlines, such as a PEM.
    _out=$(curl -sS -w '\n%{http_code}' \
        --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_MAX_TIME" \
        "$@" "$_url" 2>"$_errf")
    _HTTP_RC=$?

    if [ "$_out" = "${_out%$'\n'*}" ]; then
        # No newline at all, so not even the write-out marker reached us:
        # curl died before producing output.  Report the code as unknown
        # rather than mistaking the marker's absence for a body.
        _HTTP_BODY="$_out"
        _HTTP_CODE='000'
    else
        _HTTP_BODY="${_out%$'\n'*}"
        _HTTP_CODE="${_out##*$'\n'}"
    fi

    _HTTP_BYTES=${#_HTTP_BODY}
    _HTTP_ERR=$(diag_oneline < "$_errf")
    return "$_HTTP_RC"
}

# -- http_ok: did the last request succeed, and say what was expected? --------
# Usage: http_ok [EXPECT]
#
# True when the last http_get/http_get_retry succeeded at the transport level
# (curl exit 0), answered 2xx, and -- if EXPECT is given -- returned a body
# containing it.
#
# This exists because the alternative is writing that condition twice: once
# here and once at each assertion site.  They drifted, and the gap was exactly
# the failure #208 is about.  A PEM truncated in transit still contains
# "BEGIN CERTIFICATE" in the half that arrived, so an assertion that greps the
# body alone reports `ok` on the very fault the retry above just gave up on.
# Under the old `curl -sfk` the truncation produced an empty capture and the
# assertion failed; capturing the partial body is strictly more informative
# and would have been strictly less correct without this.
#
# http_get_retry's own success test below is this same function, so the two can
# no longer disagree.
http_ok() {  # [expect]
    [ "$_HTTP_RC" -eq 0 ] && [ "${_HTTP_CODE#2}" != "$_HTTP_CODE" ] &&
        { [ -z "${1:-}" ] || printf '%s' "$_HTTP_BODY" | grep -qF -- "$1"; }
}

# -- http_get: one request ----------------------------------------------------
# Usage: http_get URL [curl-arg...]
#
# Returns curl's exit status, so `http_get "$url" || true` reads the same as
# the code it replaces -- but the evidence survives either way, in _HTTP_INFO.
http_get() {
    _http_do "$@"
    local _rc=$?
    _HTTP_ATTEMPTS=1
    _http_set_info
    return "$_rc"
}

# -- http_get_retry: bounded retry, for fixture fetches only ------------------
# Usage: http_get_retry EXPECT URL [curl-arg...]
#
# EXPECT is a fixed string the body must contain for an attempt to count as a
# success; pass '' to require only a 2xx.  Requiring the substring is what
# makes this cover the failure #208 could not rule out, where the transfer
# looked fine at the HTTP level but the body that arrived was not a
# certificate: a retry keyed only on the exit status would have declared that
# attempt good.
#
# The wall-clock bound is HTTP_RETRY_ATTEMPTS x (HTTP_MAX_TIME + HTTP_RETRY_DELAY).
#
# ONLY for pre-flight checks against the old Puppet Server, which is fixture
# rather than the behaviour under test.  Never use it for an assertion about
# openvox-ca's own conduct: retrying there would convert exactly the
# intermittent fault worth reporting into a green run, which is the failure
# mode this whole change exists to prevent.
#
# Returns 0 on success, 1 when every attempt failed.  _HTTP_* describe the
# last attempt.
http_get_retry() {
    local _expect="$1" _url="$2"; shift 2
    local _attempt=0

    while :; do
        _attempt=$(( _attempt + 1 ))
        _http_do "$_url" "$@"
        _HTTP_ATTEMPTS=$_attempt

        if http_ok "$_expect"; then
            _http_set_info
            return 0
        fi

        [ "$_attempt" -ge "$HTTP_RETRY_ATTEMPTS" ] && break

        _http_set_info
        printf '# retry %d/%d for %s (%s)\n' \
            "$_attempt" "$HTTP_RETRY_ATTEMPTS" "$_url" "$_HTTP_INFO"
        sleep "$HTTP_RETRY_DELAY"
    done

    _http_set_info
    return 1
}
