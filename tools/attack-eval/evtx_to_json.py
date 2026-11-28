#!/usr/bin/env python3
"""
Convert EVTX-ATTACK-SAMPLES (sbousseaden) .evtx files to the flat ndjson event
shape the F.A.N.G.S telemetry eval reads (top-level Channel, EventID, and the
EventData fields spread to the top level — Image, CommandLine, TargetObject…).

These are curated MALICIOUS captures organised by ATT&CK TACTIC (folder), with
no per-file technique label, so evtx-eval scores capture-level DETECTION RATE
("did any rule fire on this real attack?") by tactic — not technique recall.

Usage: python3 tools/attack-eval/evtx_to_json.py <evtx-dir> <out-cache-dir>
Needs: pip install evtx   (pyevtx-rs, Rust-backed)
"""
import json
import os
import re
import sys

from evtx import PyEvtxParser

# Repo folder → ATT&CK tactic. Non-tactic folders fold into "other".
TACTIC = {
    "Privilege Escalation": "privilege-escalation",
    "Lateral Movement": "lateral-movement",
    "Credential Access": "credential-access",
    "Defense Evasion": "defense-evasion",
    "Execution": "execution",
    "Persistence": "persistence",
    "Discovery": "discovery",
    "Command and Control": "command-and-control",
    "Collection": "collection",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
    "Initial Access": "initial-access",
}
SKIP_FOLDERS = {"EVTX_ATT&CK_Metadata"}


def flatten(rec_json):
    """One evtx record JSON → flat event dict, or None to skip."""
    d = json.loads(rec_json)
    ev = d.get("Event", d)
    system = ev.get("System", {}) or {}
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    try:
        eid = int(eid)
    except (TypeError, ValueError):
        return None
    out = {"Channel": system.get("Channel"), "EventID": eid}
    data = ev.get("EventData") or ev.get("UserData") or {}
    if isinstance(data, dict):
        inner = data.get("Data") if set(data.keys()) <= {"Data"} else data
        if isinstance(inner, list):  # classic [{"@Name":k,"#text":v}] form
            for item in inner:
                if isinstance(item, dict) and "@Name" in item:
                    out[item["@Name"]] = item.get("#text")
        else:
            for k, v in data.items():
                if not str(k).startswith("@"):
                    out[k] = v
    return out


def sanitize(path, root):
    rel = os.path.relpath(path, root)
    return re.sub(r"[^A-Za-z0-9]+", "_", rel[:-5]).strip("_")  # drop .evtx, slugify


def main():
    evtx_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    index = []
    for dirpath, _dirs, files in os.walk(evtx_dir):
        top = os.path.relpath(dirpath, evtx_dir).split(os.sep)[0]
        if top in SKIP_FOLDERS:
            continue
        tactic = TACTIC.get(top, "other")
        for name in files:
            if not name.lower().endswith(".evtx"):
                continue
            src = os.path.join(dirpath, name)
            cid = sanitize(src, evtx_dir)
            events = []
            try:
                parser = PyEvtxParser(src)
                for rec in parser.records_json():
                    try:
                        e = flatten(rec["data"])
                    except Exception:
                        e = None
                    if e:
                        events.append(e)
            except Exception as exc:  # unreadable file — skip, never fake it
                print(f"  skip {cid}: {exc}", file=sys.stderr)
                continue
            if not events:
                continue
            with open(os.path.join(out_dir, cid + ".ndjson"), "w", encoding="utf-8") as fh:
                for e in events:
                    fh.write(json.dumps(e) + "\n")
            index.append({"id": cid, "tactic": tactic, "folder": top, "events": len(events)})
    index.sort(key=lambda x: (x["tactic"], x["id"]))
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump({"source": "EVTX-ATTACK-SAMPLES (github.com/sbousseaden), tactic-labeled malicious captures", "captures": index}, fh, indent=1)
    by_tactic = {}
    for c in index:
        by_tactic[c["tactic"]] = by_tactic.get(c["tactic"], 0) + 1
    print(f"converted {len(index)} captures → {out_dir}")
    print("by tactic:", json.dumps(by_tactic))


if __name__ == "__main__":
    main()
