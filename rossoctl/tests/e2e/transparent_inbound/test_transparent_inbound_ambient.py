"""Inbound validation on the Istio ambient / HBONE path (rossoctl/cortex#780, part 3).

The other modules dial the agent from another pod and assert a denial. On a
cluster with no ztunnel that request reaches the pod as ordinary TCP and is
captured in `nat PREROUTING` by `AB_INBOUND`. Under ambient it does not: ztunnel
terminates HBONE on `:15008` and **re-originates** a local connection to the
workload, which never traverses `PREROUTING` at all. It surfaces in `nat OUTPUT`
instead, and is captured by a separate mark-based DNAT at the head of
`AB_REDIRECT` — ahead of that chain's ztunnel-mark `RETURN`, which would
otherwise wave it straight through to the app.

So the two paths are captured by two different rules, and the hazard #780 names
is that a `PREROUTING`-only implementation looks entirely correct while passing
every mesh-delivered request to the app unvalidated. Nothing in the other modules
can tell the difference: both paths end in the same 401.

That is why `test_hbone_delivered_request_is_validated` asserts the *path* as
well as the outcome. Without the path assertion this module silently degrades
into a duplicate of `test_direct_pod_dial_is_validated` the moment ambient is
absent or stops being engaged — green, and testing nothing new.

Rule ordering and packet counters are not asserted here; they are not reachable
from a test pod, and they do not need to be. Every way the ambient DNAT can
regress — deleted, placed after the mark `RETURN`, or matching too narrowly —
ends with the app answering the mesh-delivered request itself, so the status code
catches it. The counter-level evidence for the rules as programmed is recorded on
rossoctl/cortex#780.

Deliberately **not** marked `kind_only`, unlike the rest of this suite: the
platform ships the ambient data plane on OpenShift only
(`charts/rossoctl-deps/templates/istio-operand.yaml` gates the `Istio`,
`IstioCNI` and `ZTunnel` operands on `.Values.openshift`), so a Kind-only ambient
test could never run where ambient actually is the shipped configuration. It
self-gates on a running ztunnel instead, which skips on Kind today and becomes a
real gate on OpenShift and on any Kind cluster with ambient installed by hand.
"""

import pytest

from .conftest import (
    AGENT_PORT,
    NS_CONTROL,
    NS_TRANSPARENT,
    agent_pod,
    curl_from_probe,
    kubectl,
    kubectl_json,
)

# AuthBridge's own health port, exempt from capture on both paths so kubelet
# probes are not gated. Same value the other module asserts against.
HEALTH_PORT = 9091

AMBIENT_LABEL = "istio.io/dataplane-mode"

# ztunnel is one DaemonSet pod per node and logs the inbound side of every HBONE
# connection it terminates. Read enough lines to survive an unrelated busy
# cluster between the request and the read.
ZTUNNEL_LOG_TAIL = "1000"


@pytest.fixture(scope="module")
def ztunnel_namespace():
    """Skip unless an ambient data plane is actually carrying traffic here.

    Two separate things have to hold, and they fail for different reasons worth
    naming separately: a ztunnel must be running (absent on a cluster installed
    without the ambient profile), and the namespaces this suite uses must be
    enrolled into it (present but not applied to these namespaces). Either way
    the request under test would arrive as plain TCP, so the module has nothing
    to say and says so rather than passing.

    Found by label across all namespaces on purpose: the platform chart puts
    ztunnel in `istio-ztunnel` while a community `istio/ztunnel` install defaults
    to `istio-system`, and which one is in front of the workload does not change
    the rule under test.
    """
    pods = kubectl_json("get", "pods", "-A", "-l", "app=ztunnel")
    ready = [
        p
        for p in pods.get("items", [])
        if p["status"].get("phase") == "Running"
        and all(c.get("ready") for c in p["status"].get("containerStatuses", []))
    ]
    if not ready:
        pytest.skip(
            "no ready ztunnel pod: this cluster has no ambient data plane, so "
            "inbound cannot arrive over HBONE and the ambient capture rule is "
            "unreachable. The platform enables ambient on OpenShift only "
            "(charts/rossoctl-deps/templates/istio-operand.yaml gates the Istio, "
            "IstioCNI and ZTunnel operands on .Values.openshift)."
        )

    for ns in (NS_TRANSPARENT, NS_CONTROL):
        labels = kubectl_json("get", "ns", ns)["metadata"].get("labels", {})
        if labels.get(AMBIENT_LABEL) != "ambient":
            pytest.skip(
                f"namespace {ns} is not ambient-enrolled "
                f"({AMBIENT_LABEL}={labels.get(AMBIENT_LABEL)!r}): traffic would "
                "arrive as plain TCP and be captured by AB_INBOUND, which the "
                "other modules already cover"
            )

    return ready[0]["metadata"]["namespace"]


def _ztunnel_log(ztunnel_ns: str) -> str:
    return kubectl(
        "logs", "-n", ztunnel_ns, "-l", "app=ztunnel", "--tail=" + ZTUNNEL_LOG_TAIL
    )


def _hbone_inbound_lines(log: str, pod_ip: str, port: int) -> int:
    """Count ztunnel access lines for HBONE *terminated at* pod_ip:port.

    `dst.hbone_addr` is only written for a connection ztunnel took off `:15008`
    and re-originated locally — precisely the path this module exists for. The
    direction filter keeps the destination ztunnel's own entry and drops the
    source side's view of the same connection, so a count difference of one
    request is one line.
    """
    needle = f"dst.hbone_addr={pod_ip}:{port}"
    return sum(
        1
        for line in log.splitlines()
        if needle in line and 'direction="inbound"' in line
    )


def _assert_arrived_over_hbone(ztunnel_ns: str, pod_ip: str, port: int, before: int):
    """Fail if the request did not reach pod_ip:port as terminated HBONE."""
    log = _ztunnel_log(ztunnel_ns)
    if _hbone_inbound_lines(log, pod_ip, port) > before:
        return
    # Distinguish "no HBONE" from "no evidence of HBONE": if ztunnel is not
    # writing access logs at all, this module cannot see the path either way, and
    # failing would name the wrong cause. Any hbone_addr line for any workload
    # proves the signal exists and its absence for ours is the real answer.
    if "dst.hbone_addr=" not in log:
        pytest.skip(
            f"ztunnel in {ztunnel_ns} is logging no HBONE connections for any "
            "workload, so the delivery path cannot be confirmed from here; "
            "refusing to claim ambient coverage on unverified traffic"
        )
    raise AssertionError(
        f"no terminated-HBONE line for {pod_ip}:{port} — the request did not "
        "arrive through ztunnel, so it exercised AB_INBOUND in nat PREROUTING "
        "and this module is duplicating test_direct_pod_dial_is_validated "
        "rather than covering the ambient DNAT. Check that the probe's namespace "
        f"({NS_CONTROL}) is still ambient-enrolled."
    )


def test_hbone_delivered_request_is_validated(ztunnel_namespace, transparent_agent):
    """A mesh-delivered request must be validated, not handed to the app.

    The assertion that closes #780's ambient half. Traffic crosses from an
    ambient namespace, so ztunnel terminates HBONE and re-originates locally,
    bypassing `PREROUTING` entirely — and the 401 can then only have come from
    the ambient DNAT having captured it in `nat OUTPUT`.
    """
    pod_ip = agent_pod(**transparent_agent)["status"]["podIP"]
    before = _hbone_inbound_lines(_ztunnel_log(ztunnel_namespace), pod_ip, AGENT_PORT)

    status = curl_from_probe(NS_CONTROL, f"http://{pod_ip}:{AGENT_PORT}/")

    _assert_arrived_over_hbone(ztunnel_namespace, pod_ip, AGENT_PORT, before)
    assert status in (401, 403), (
        f"mesh-delivered request to :{AGENT_PORT} returned {status}, want an auth "
        "denial. It reached the pod over HBONE and was answered without "
        "validation, which is the ambient bypass #780 tracks: the ambient DNAT at "
        "the head of AB_REDIRECT is missing, ordered after that chain's "
        "ztunnel-mark RETURN, or matching too narrowly."
    )


def test_health_port_exempt_on_the_hbone_path(ztunnel_namespace, transparent_agent):
    """The port exemptions have to hold on the ambient path too.

    They are a separate set of rules from the ones the other module exercises —
    same ports, but re-stated with the ztunnel-mark match in `AB_REDIRECT`. If
    they were dropped there, or ordered after the DNAT, `:9091` would go through
    the pipeline and kubelet probes on a meshed pod would start failing.

    Asserts reachable-and-unauthenticated, not merely "not 401": a health port
    that stopped answering entirely would also stop failing probes' auth check.
    """
    pod_ip = agent_pod(**transparent_agent)["status"]["podIP"]
    before = _hbone_inbound_lines(_ztunnel_log(ztunnel_namespace), pod_ip, HEALTH_PORT)

    status = curl_from_probe(NS_CONTROL, f"http://{pod_ip}:{HEALTH_PORT}/healthz")

    _assert_arrived_over_hbone(ztunnel_namespace, pod_ip, HEALTH_PORT, before)
    assert status == 200, (
        f"health port {HEALTH_PORT} returned {status} on the ambient path, want "
        "200. Under ambient the exemptions are re-stated in AB_REDIRECT with the "
        "ztunnel-mark match; a 401 means they are missing or ordered after the "
        "DNAT, and probes on a meshed pod would fail."
    )
