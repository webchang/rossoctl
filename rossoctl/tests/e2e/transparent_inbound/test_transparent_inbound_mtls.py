"""Inbound mTLS through the transparent listener (rossoctl/cortex#780, part 2).

The transparent listener reuses the reverse proxy's mTLS posture via
`WrapListener`, so `tlssniff` handles permissive/strict identically for both
inbound shapes. Startup logs confirmed the wrap was active, but nothing had ever
driven TLS at it — and the untested part is specifically the *combination*:
`SO_ORIGINAL_DST` recovery happens on the raw connection, before `tlssniff`
peeks the first byte. If those two interfered, the logs would still look correct.

Three cases, in increasing strength:

  A. strict + plaintext        -> connection closed, no HTTP (tlssniff is engaged)
  B. strict + TLS, no cert     -> TLS alert (server-side TLS really terminates)
  C. strict + TLS, valid SVID  -> handshake COMPLETES, pipeline runs (401)

C is the one that matters: it proves the whole chain — REDIRECT, destination
recovery, TLS termination, client-cert verification, then the inbound pipeline.
B doubles as C's control: the same endpoint refuses a caller that presents no
certificate, so C's 401 cannot be explained by verification being lax.
"""

import json

import pytest

from .conftest import AGENT_PORT, PROBE_IMAGE, agent_pod, kubectl
from .conftest import SVID_SECRET_NAME as SVID_SECRET

pytestmark = pytest.mark.kind_only


def _curl(namespace: str, name: str, script: str, svid: bool = False) -> str:
    """Run a shell snippet in a throwaway pod and return its combined output.

    With svid=True the staged SVID Secret is mounted at /svid. That needs
    ``--overrides``, which is a JSON *merge* patch: it replaces the generated
    container list wholesale rather than merging into it, so the override has to
    restate command/image/stdin itself. Omitting the command leaves the probe
    running the image's default entrypoint, which never exits — the pod hangs
    until kubectl's timeout instead of failing an assertion.
    """
    args = [
        "run",
        name,
        "-n",
        namespace,
        "--rm",
        "-i",
        "--restart=Never",
        "--image=" + PROBE_IMAGE,
        "--image-pull-policy=IfNotPresent",
        "--quiet",
    ]
    if svid:
        args.append("--overrides=" + _svid_overrides(name, script))
    args += ["--command", "--", "sh", "-c", script]
    return kubectl(*args, check=False)


def _svid_overrides(name: str, script: str) -> str:
    """Pod overrides mounting the staged SVID at /svid."""
    return json.dumps(
        {
            "spec": {
                "volumes": [{"name": "svid", "secret": {"secretName": SVID_SECRET}}],
                "containers": [
                    {
                        "name": name,
                        "image": PROBE_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["sh", "-c", script],
                        "stdin": True,
                        "stdinOnce": True,
                        "volumeMounts": [
                            {"name": "svid", "mountPath": "/svid", "readOnly": True}
                        ],
                    }
                ],
            }
        }
    )


def test_strict_rejects_plaintext(mtls_strict_agent):
    """A: strict must refuse a non-TLS caller on the transparent listener.

    This is the cheapest proof that `tlssniff` is actually in the path: the same
    request returns 401 under permissive (see the main module), so a closed
    connection here can only come from the sniffer rejecting the first byte.
    """
    pod = agent_pod(**mtls_strict_agent)
    ip = pod["status"]["podIP"]
    out = _curl(
        mtls_strict_agent["namespace"],
        "ti-mtls-plain",
        f'curl -sS -o /dev/null -w "code=%{{http_code}}" --max-time 15 '
        f"http://{ip}:{AGENT_PORT}/ 2>&1 | tail -2",
    )
    assert "code=200" not in out, (
        f"strict mTLS served a plaintext caller — tlssniff is not in the "
        f"transparent path:\n{out}"
    )
    assert "code=401" not in out, (
        f"strict mTLS ran the pipeline for a plaintext caller instead of "
        f"rejecting the connection:\n{out}"
    )
    # curl reports a closed connection as (52) Empty reply, or a reset.
    assert "code=000" in out, f"expected no HTTP response at all, got:\n{out}"


def test_strict_terminates_tls_on_the_recovered_connection(mtls_strict_agent):
    """B: a TLS ClientHello must reach a real server-side handshake.

    The alert is the evidence: to demand a client certificate the server had to
    send its own certificate first, which means TLS terminated on the connection
    the transparent listener recovered via SO_ORIGINAL_DST.
    """
    pod = agent_pod(**mtls_strict_agent)
    ip = pod["status"]["podIP"]
    out = _curl(
        mtls_strict_agent["namespace"],
        "ti-mtls-nocert",
        f'curl -sS -k -o /dev/null -w "code=%{{http_code}}" --max-time 15 '
        f"https://{ip}:{AGENT_PORT}/ 2>&1 | tail -3",
    )
    # Specifically a *missing client certificate* alert, not any alert at all: this
    # case is C's control, so accepting e.g. a handshake_failure would let it pass
    # for reasons unrelated to client-cert verification. Go's tls.Server sends
    # certificate_required under TLS 1.3 and bad_certificate under 1.2 when a
    # caller presents no certificate, so both spellings are legitimate here.
    lowered = out.lower()
    assert "certificate required" in lowered or "bad certificate" in lowered, (
        "expected a TLS alert demanding a client certificate, which is what proves "
        f"server-side TLS terminated here:\n{out}"
    )


def test_strict_completes_mtls_and_still_enforces(mtls_strict_agent, svid_secret):
    """C: a valid SVID completes the handshake, and the pipeline still runs.

    401, not 200: authentication of the *transport* must not be mistaken for
    authorization of the *request*. Reaching 401 means the request traversed
    REDIRECT -> SO_ORIGINAL_DST -> tlssniff -> tls.Server (client cert verified)
    -> jwt-validation.
    """
    pod = agent_pod(**mtls_strict_agent)
    ip = pod["status"]["podIP"]
    ns = mtls_strict_agent["namespace"]
    name = mtls_strict_agent["name"]
    host = f"{name}.{ns}.svc.cluster.local"
    # --resolve so SNI/Host match the SVID's DNS SANs while still dialing the pod
    # IP directly: via the Service the request would be indistinguishable from the
    # Service-routed case this module is not testing.
    script = (
        f'curl -sS -o /dev/null -w "code=%{{http_code}}" --max-time 20 '
        f"--cert /svid/svid.pem --key /svid/svid_key.pem "
        f"--cacert /svid/svid_bundle.pem "
        f'--resolve "{host}:{AGENT_PORT}:{ip}" '
        f"https://{host}:{AGENT_PORT}/ 2>&1 | tail -3"
    )
    out = _curl(ns, "ti-mtls-svid", script, svid=True)
    assert "code=401" in out, (
        "expected 401: a completed mTLS handshake followed by the inbound pipeline "
        f"rejecting a request with no bearer token. Got:\n{out}"
    )
