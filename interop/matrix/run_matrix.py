#!/usr/bin/env python3
"""Cross-language interop matrix: 3 flows x every host/guest pair of peers.

Each peer is a program that speaks `haven.interop-peer.v1` on stdin/stdout
(see README.md). Give one per language:

    python3 interop/matrix/run_matrix.py \
        --peer python="python3 -m cellprotocol_scaffold.interop_peer" \
        --peer go="/path/to/interop-peer" \
        --peer swift="/path/to/InteropPeer" \
        --out TESTRESULT.md

Flows, for host H and guest G:
- extend: G (new device) asks to join H's entity, H reviews and signs the
  approval, G verifies it. A stranger's approval is refused by G.
- invite: H issues an invitation and publishes it on H's own landing, G
  verifies the link, replies by short code, H sees "joined", pulls and
  verifies the reply once, and a revoked link refuses G's reply.
- chat: H hosts a chat on its node and invites G, G signs the acceptance on
  its own node, joins over the authenticated bridge, sends and reads. A
  stranger, owner-only keys and a revoked guest are refused.

Exit code 0 only when every step of every cell passes.
"""

import argparse
import itertools
import json
import shlex
import subprocess
import sys
import time

AUDIENCE = "https://staging.haven.digipomps.org"


class PeerError(Exception):
    pass


class Peer:
    def __init__(self, lang: str, command: str, name: str):
        self.lang = lang
        self.proc = subprocess.Popen(shlex.split(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        hello = self.op("hello")
        if hello.get("protocol") != "haven.interop-peer.v1":
            raise PeerError(f"{lang} peer speaks {hello}")
        init = self.op("init", name=name)
        self.identity, self.descriptor = init["identity"], init["descriptor"]
        self.uuid = self.identity["uuid"]

    def op(self, op: str, **fields):
        self.proc.stdin.write(json.dumps({"op": op, **fields}) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise PeerError(f"{self.lang} peer exited")
        reply = json.loads(line)
        if not reply.get("ok"):
            raise PeerError(reply.get("error", "refused"))
        return reply.get("result")

    def set(self, cell, key, value=None):
        return self.op("call", cell=cell, method="set", key=key, value=value)

    def get(self, cell, key):
        return self.op("call", cell=cell, method="get", key=key)

    def remote(self, url, method, key, value=None):
        return self.op("remote", url=url, method=method, key=key, value=value)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            self.proc.kill()


def refused(fn) -> bool:
    """A refusal is ok: false from the peer or an "error..." result string."""
    try:
        result = fn()
    except PeerError:
        return True
    return isinstance(result, str) and result.startswith("error")


class Steps:
    def __init__(self):
        self.done: list[tuple[str, bool, str]] = []

    def check(self, name, ok, detail=""):
        self.done.append((name, bool(ok), "" if ok else str(detail)[:400]))
        return ok

    def run(self, name, fn):
        try:
            return fn()
        except Exception as error:  # noqa: BLE001
            self.check(name, False, f"{type(error).__name__}: {error}")
            raise


# ---- flows ---------------------------------------------------------------------------


def flow_extend(host: Peer, guest: Peer, stranger: Peer, steps: Steps, _node: dict):
    asked = guest.set("extension", "extension.beginRequest", {"audience": AUDIENCE})
    steps.check("guest builds request", isinstance(asked, dict) and asked.get("payload"), asked)
    review = host.set("extension", "extension.reviewRequest", asked["payload"])
    steps.check("host reviews, same human code", review.get("status") == "reviewable" and review.get("humanCode") == asked.get("humanCode"), review)
    approved = host.set("extension", "extension.approveRequest", asked["payload"])
    steps.check("host signs approval", isinstance(approved, dict) and approved.get("payload"), approved)
    accepted = guest.set("extension", "extension.acceptApproval", {"payload": approved["payload"], "issuerIdentity": approved["issuerIdentity"]})
    steps.check("guest verifies approval signature", accepted.get("status") == "ok" and accepted.get("signatureVerified") is True, accepted)
    other = stranger.set("extension", "extension.beginRequest", {"audience": AUDIENCE})
    foreign = host.set("extension", "extension.approveRequest", other["payload"])
    guest.set("extension", "extension.beginRequest", {"audience": AUDIENCE})
    wrong = guest.set("extension", "extension.acceptApproval", {"payload": foreign["payload"], "issuerIdentity": foreign["issuerIdentity"]})
    steps.check("guest refuses an approval for someone else's request", not (isinstance(wrong, dict) and wrong.get("status") == "ok"), wrong)


def flow_invite(host: Peer, guest: Peer, _stranger: Peer, steps: Steps, node: dict):
    base = node["landingBase"]
    port = base.rsplit(":", 1)[-1]
    host.op("invitation", landingBase=base, contactEndpointID=f"ep-{host.uuid}")
    guest.op("invitation", landingBase=base)
    p = host.set("invitation", "invite.prepare", {"recipient": f"guest+{port}@example.org", "recipientDisplayName": "Guest"})
    steps.check("host prepares and publishes on its landing", p.get("status") == "ok" and p.get("published") and p["link"].endswith("/i/" + p["humanCode"]), p)
    verdict = guest.set("invitation", "invite.verify", {"link": p["selfContainedLink"]})
    steps.check("guest verifies the long link", verdict.get("code") == "valid", verdict)
    reply = guest.set("invitation", "invite.respond", {"link": p["link"], "message": f"hei fra {guest.lang}"})
    steps.check("guest replies via short code", reply.get("status") == "ok", reply)
    status = host.set("invitation", "invite.refreshStatus", {})
    steps.check("host sees joined", (status.get("outbox") or [{}])[0].get("state") == "joined", status)
    pulled = host.set("invitation", "invite.pullContactRequests", {})
    steps.check("host pulls and verifies the reply", pulled.get("receivedCount") == 1 and pulled["inbox"][0].get("message") == f"hei fra {guest.lang}", pulled)
    steps.check("reply is collected once", host.set("invitation", "invite.pullContactRequests", {}).get("receivedCount") == 0)
    p2 = host.set("invitation", "invite.prepare", {"recipient": f"guest2+{port}@example.org"})
    host.set("invitation", "invite.revoke", {"ticketID": p2["ticketID"]})
    late = guest.set("invitation", "invite.respond", {"link": p2["selfContainedLink"]})
    steps.check("revoked link refuses the reply", late.get("code") == "not_active", late)


def flow_chat(host: Peer, guest: Peer, stranger: Peer, steps: Steps, node: dict):
    url = node["chatURL"]
    host.set("chat", "audience.inviteIdentities", [guest.identity])
    artifact = host.set("chat", "audience.generateInvitationArtifacts", True)[0]
    host.op("admit", identity=guest.identity)
    acceptance = guest.set("home", "audience.generateInvitationAcceptance", artifact)
    steps.check("guest signs acceptance on its own node", isinstance(acceptance, dict) and acceptance.get("invitationID") == artifact.get("invitationID"), acceptance)
    steps.check("guest refused before accepting", refused(lambda: guest.remote(url, "get", "messages")))
    accepted = guest.remote(url, "set", "audience.acceptInvitationArtifact", {"artifact": artifact, "acceptance": acceptance})
    steps.check("host verifies both signatures and admits", isinstance(accepted, dict) and accepted.get("status") == "accepted", accepted)
    sent = guest.remote(url, "set", "sendMessage", f"Hei fra {guest.lang}")
    steps.check("guest sends over the bridge", isinstance(sent, dict) and sent.get("status") == "sent", sent)
    host.set("chat", "sendMessage", f"Hei tilbake fra {host.lang}")
    messages = guest.remote(url, "get", "messages")
    contents = [m.get("content") for m in messages] if isinstance(messages, list) else messages
    steps.check("guest reads both messages", contents == [f"Hei fra {guest.lang}", f"Hei tilbake fra {host.lang}"], messages)
    owners = [m.get("ownerUUID") for m in host.get("chat", "messages")]
    steps.check("host attributes the message to the guest", owners == [guest.uuid, host.uuid], owners)
    steps.check("stranger refused", refused(lambda: stranger.remote(url, "set", "sendMessage", "slipp meg inn")))
    steps.check("member refused on owner keys", refused(lambda: guest.remote(url, "set", "audience.generateInvitationArtifacts", True)))
    host.set("chat", "audience.revokeInvites", [guest.uuid])
    steps.check("revoked guest refused", refused(lambda: guest.remote(url, "get", "messages")))


FLOWS = [("extend", flow_extend), ("invite", flow_invite), ("chat", flow_chat)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--peer", action="append", required=True, help="lang=command")
    parser.add_argument("--out", help="write the result table (Markdown) here")
    parser.add_argument("--port", type=int, default=18200, help="first local port")
    parser.add_argument("--flows", default=",".join(name for name, _ in FLOWS), help="comma-separated subset of extend,invite,chat")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    peers = dict(p.split("=", 1) for p in args.peer)
    flows = [(name, fn) for name, fn in FLOWS if name in args.flows.split(",")]
    langs = list(peers)
    port = args.port
    table: dict[tuple[str, str, str], tuple[int, int, list]] = {}
    for host_lang, guest_lang in itertools.product(langs, repeat=2):
        started = []
        try:
            host = Peer(host_lang, peers[host_lang], "Alice"); started.append(host)
            guest = Peer(guest_lang, peers[guest_lang], "Bob"); started.append(guest)
            stranger = Peer(guest_lang, peers[guest_lang], "Mallory"); started.append(stranger)
            node = host.op("serve", port=port)
            for flow, fn in flows:
                steps = Steps()
                try:
                    fn(host, guest, stranger, steps, node)
                except Exception as error:  # noqa: BLE001
                    if not steps.done or steps.done[-1][1]:
                        steps.check("flow ran to the end", False, f"{type(error).__name__}: {error}")
                passed = sum(ok for _, ok, _ in steps.done)
                table[(flow, host_lang, guest_lang)] = (passed, len(steps.done), steps.done)
                mark = "OK  " if passed == len(steps.done) else "FAIL"
                print(f"{mark} {flow:6} host={host_lang:6} guest={guest_lang:6} {passed}/{len(steps.done)}")
                for name, ok, detail in steps.done:
                    if args.verbose or not ok:
                        print(f"       {'ok ' if ok else 'XX '} {name}" + (f"  {detail}" if detail else ""))
        except Exception as error:  # noqa: BLE001
            for flow, _ in flows:
                table.setdefault((flow, host_lang, guest_lang), (0, 1, [("peer started", False, str(error))]))
            print(f"FAIL host={host_lang} guest={guest_lang}: {error}")
        finally:
            for peer in started:
                peer.close()
            port += 1
    all_green = all(p == n for p, n, _ in table.values())
    if args.out:
        pairs = list(itertools.product(langs, repeat=2))
        lines = [
            "# Interop matrix",
            "",
            f"Run {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}. Columns are host → guest. Each cell is steps passed / steps run.",
            "",
            "| flow | " + " | ".join(f"{h} → {g}" for h, g in pairs) + " |",
            "|---|" + "---|" * len(pairs),
        ]
        for flow, _ in flows:
            cells = []
            for h, g in pairs:
                p, n, _ = table[(flow, h, g)]
                cells.append(f"{'✅' if p == n else '❌'} {p}/{n}")
            lines.append(f"| {flow} | " + " | ".join(cells) + " |")
        failures = [(k, s) for k, (p, n, s) in table.items() if p != n]
        if failures:
            lines += ["", "## Failed steps", ""]
            for (flow, h, g), steps_done in failures:
                for name, ok, detail in steps_done:
                    if not ok:
                        lines.append(f"- {flow} {h} → {g}: {name}. {detail}")
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    print("all green" if all_green else "NOT all green")
    return 0 if all_green else 1


if __name__ == "__main__":
    sys.exit(main())
