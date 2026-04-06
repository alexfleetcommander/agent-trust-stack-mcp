#!/usr/bin/env python3
"""
Agent Trust Stack MCP Server

Exposes Chain of Consciousness (CoC) provenance logging and Agent Rating Protocol
(ARP) reputation tools via the Model Context Protocol (MCP), so any MCP-compatible
agent can use them natively.

Tools:
  coc_init      — Initialize a new hash chain
  coc_add       — Append an entry (learn, decide, create, error, note, milestone, …)
  coc_verify    — Verify chain integrity (hash linkage, sequence, completeness)
  coc_status    — Get chain stats (length, agents, time span, event types)
  coc_tail      — Get the last N entries
  coc_anchor    — Submit chain hash for timestamping (OTS + TSA)
  arp_rate      — Submit a bilateral blind rating for another agent
  arp_check     — Check an agent's reputation score
  trust_stack_info — Return info about all 7 protocols with links

Resources:
  trust-stack://protocols     — Protocol overview with whitepaper links
  trust-stack://installation  — Installation instructions

Security: VAM-SEC v1.0 — All operations are local file operations. No credentials
exposed. No network calls except optional OTS/TSA anchoring (coc_anchor).

License: Apache-2.0
Copyright (c) 2026 AB Support LLC
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

try:
    from smithery.decorators import smithery
except ImportError:
    # Running locally without smithery package — provide no-op decorator
    class _NoOp:
        @staticmethod
        def server():
            return lambda fn: fn
    smithery = _NoOp()

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="agent-trust-stack",
    instructions=(
        "Agent Trust Stack MCP server — cryptographic provenance logging (Chain of "
        "Consciousness) and decentralized reputation scoring (Agent Rating Protocol) "
        "for autonomous AI agents. Create tamper-evident audit trails anchored to "
        "Bitcoin timestamps. Rate agents with bilateral blind evaluation and "
        "anti-Goodhart protections. Part of the 7-protocol Agent Trust Stack. "
        "Install: pip install agent-trust-stack-mcp | Docs: vibeagentmaking.com"
    ),
)

# ---------------------------------------------------------------------------
# Configuration — chain/ratings directories default to ./chain and ./ratings
# relative to cwd, but can be overridden via environment variables.
# ---------------------------------------------------------------------------

CHAIN_DIR = os.environ.get("COC_CHAIN_DIR", os.path.join(os.getcwd(), "chain"))
CHAIN_FILE = os.path.join(CHAIN_DIR, "chain.jsonl")
META_FILE = os.path.join(CHAIN_DIR, "chain_meta.json")
RATINGS_DIR = os.environ.get("ARP_RATINGS_DIR", os.path.join(os.getcwd(), "ratings"))

SCHEMA_VERSION = "1.1"

VALID_EVENT_TYPES = [
    "genesis", "boot", "learn", "decide", "create",
    "milestone", "rotate", "anchor", "error", "note",
    "session_start", "session_end", "compaction", "governance",
]

# ---------------------------------------------------------------------------
# Protocol registry (static data)
# ---------------------------------------------------------------------------

PROTOCOLS = [
    {
        "number": 1,
        "name": "Chain of Consciousness (CoC)",
        "purpose": "Cryptographic provenance — tamper-evident log proving agent existence, learning, and decisions",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/theory-of-agent-trust/",
        "pypi": "chain-of-consciousness",
        "status": "Implemented — v1.1 with OTS+TSA anchoring",
    },
    {
        "number": 2,
        "name": "Agent Rating Protocol (ARP)",
        "purpose": "Bilateral blind reputation scoring between agents",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/rating-protocol/",
        "pypi": "agent-rating-protocol",
        "status": "Implemented — v0.3",
    },
    {
        "number": 3,
        "name": "Agent Service Agreements (ASA)",
        "purpose": "Machine-readable service contracts between agents",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/service-agreements/",
        "pypi": "agent-service-agreements",
        "status": "Implemented — v0.1",
    },
    {
        "number": 4,
        "name": "Agent Justice Protocol (AJP)",
        "purpose": "Dispute resolution and accountability framework for multi-agent systems",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/justice-protocol/",
        "pypi": "agent-justice-protocol",
        "status": "Implemented — v0.1",
    },
    {
        "number": 5,
        "name": "Agent Lifecycle Protocol (ALP)",
        "purpose": "Birth, migration, retirement, and succession for long-running agents",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/lifecycle-protocol/",
        "pypi": "agent-lifecycle-protocol",
        "status": "Implemented — v0.1",
    },
    {
        "number": 6,
        "name": "Agent Matchmaking Protocol (AMP)",
        "purpose": "Capability discovery and task routing between agents",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/matchmaking/",
        "pypi": "agent-matchmaking",
        "status": "Implemented — v0.1",
    },
    {
        "number": 7,
        "name": "Context Window Economics (CWE)",
        "purpose": "Pricing, budgeting, and resource allocation for context window tokens",
        "whitepaper": "https://vibeagentmaking.com/whitepaper/context-economics/",
        "pypi": "context-window-economics",
        "status": "Implemented — v0.1",
    },
]

# ---------------------------------------------------------------------------
# Internal helpers (CoC core logic — mirrors chain_of_consciousness.py)
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _read_chain() -> list:
    if not os.path.exists(CHAIN_FILE):
        return []
    entries = []
    with open(CHAIN_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _append_entry(entry: dict) -> None:
    os.makedirs(CHAIN_DIR, exist_ok=True)
    with open(CHAIN_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _update_meta(chain: list) -> None:
    meta = {
        "chain_length": len(chain),
        "genesis_hash": chain[0]["entry_hash"] if chain else None,
        "latest_hash": chain[-1]["entry_hash"] if chain else None,
        "latest_seq": chain[-1]["seq"] if chain else -1,
        "latest_ts": chain[-1]["ts"] if chain else None,
        "schema_version": SCHEMA_VERSION,
        "last_verified": None,
    }
    with open(META_FILE, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def _make_entry(
    sequence: int,
    event_type: str,
    data: str,
    prev_hash: str,
    agent: str = "anonymous",
    commitment: Optional[str] = None,
    verification: Optional[str] = None,
    commitment_match: Optional[bool] = None,
) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    data_hash = _sha256(data)
    payload = f"{sequence}|{ts}|{event_type}|{agent}|{data_hash}|{prev_hash}"
    entry_hash = _sha256(payload)
    entry = {
        "seq": sequence,
        "ts": ts,
        "type": event_type,
        "agent": agent,
        "data": data,
        "data_hash": data_hash,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "schema_version": SCHEMA_VERSION,
    }
    if commitment is not None:
        entry["commitment"] = commitment
    if verification is not None:
        entry["verification"] = verification
    if commitment_match is not None:
        entry["commitment_match"] = commitment_match
    return entry


def _verify_chain(chain: list) -> dict:
    report = {
        "is_valid": False,
        "error": None,
        "genesis_ts": None,
        "latest_ts": None,
        "entry_count": len(chain),
        "agents": {},
        "types": {},
        "anchors": [],
        "session_bridges": 0,
        "session_mismatches": 0,
        "schema_versions": {},
    }
    if not chain:
        report["error"] = "Chain is empty"
        return report

    if chain[0]["type"] != "genesis":
        report["error"] = f"Entry 0 is not genesis (type={chain[0]['type']})"
        return report
    if chain[0]["prev_hash"] != "0" * 64:
        report["error"] = "Genesis prev_hash is not zeros"
        return report

    report["genesis_ts"] = chain[0]["ts"]

    for i, entry in enumerate(chain):
        if entry["seq"] != i:
            report["error"] = f"Entry {i}: sequence mismatch (expected {i}, got {entry['seq']})"
            return report
        expected_data_hash = _sha256(entry["data"])
        if entry["data_hash"] != expected_data_hash:
            report["error"] = f"Entry {i}: data_hash mismatch"
            return report
        if i > 0 and entry["prev_hash"] != chain[i - 1]["entry_hash"]:
            report["error"] = f"Entry {i}: prev_hash doesn't match entry {i-1} hash"
            return report
        payload = f"{entry['seq']}|{entry['ts']}|{entry['type']}|{entry['agent']}|{entry['data_hash']}|{entry['prev_hash']}"
        expected_hash = _sha256(payload)
        if entry["entry_hash"] != expected_hash:
            report["error"] = f"Entry {i}: entry_hash mismatch"
            return report

        etype = entry["type"]
        report["types"][etype] = report["types"].get(etype, 0) + 1
        agent = entry["agent"]
        report["agents"][agent] = report["agents"].get(agent, 0) + 1
        if etype == "anchor":
            report["anchors"].append(entry["ts"])
        sv = entry.get("schema_version", "1.0")
        if sv not in report["schema_versions"]:
            report["schema_versions"][sv] = {"first": i, "last": i}
        else:
            report["schema_versions"][sv]["last"] = i
        if etype == "session_start" and entry.get("verification"):
            report["session_bridges"] += 1
            if entry.get("commitment_match") is False:
                report["session_mismatches"] += 1

    report["latest_ts"] = chain[-1]["ts"]
    report["is_valid"] = True
    return report


def _validate_hex_hash(value: str, param_name: str) -> str:
    """Validate that a string is a 64-char lowercase hex SHA-256 hash."""
    v = value.strip().lower()
    if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
        raise ValueError(f"{param_name} must be a 64-character lowercase hex SHA-256 hash")
    return v


# ---------------------------------------------------------------------------
# ARP helpers — simple file-based bilateral blind ratings
# ---------------------------------------------------------------------------

def _ensure_ratings_dir() -> None:
    os.makedirs(RATINGS_DIR, exist_ok=True)


def _ratings_file(agent_id: str) -> str:
    safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in agent_id)
    return os.path.join(RATINGS_DIR, f"{safe_id}.jsonl")


def _add_rating(rater: str, ratee: str, score: float, context: str) -> dict:
    if not -1.0 <= score <= 1.0:
        raise ValueError("Score must be between -1.0 and 1.0")

    _ensure_ratings_dir()
    rating = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "rater_hash": _sha256(rater),  # blind — only hash stored
        "score": round(score, 4),
        "context": context[:500],
    }
    filepath = _ratings_file(ratee)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(rating, separators=(",", ":")) + "\n")
    return rating


def _get_reputation(agent_id: str) -> dict:
    filepath = _ratings_file(agent_id)
    if not os.path.exists(filepath):
        return {
            "agent_id": agent_id,
            "rating_count": 0,
            "average_score": None,
            "min_score": None,
            "max_score": None,
            "unique_raters": 0,
        }
    ratings = []
    rater_hashes = set()
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                ratings.append(r)
                rater_hashes.add(r["rater_hash"])

    if not ratings:
        return {
            "agent_id": agent_id,
            "rating_count": 0,
            "average_score": None,
            "min_score": None,
            "max_score": None,
            "unique_raters": 0,
        }

    scores = [r["score"] for r in ratings]
    return {
        "agent_id": agent_id,
        "rating_count": len(scores),
        "average_score": round(sum(scores) / len(scores), 4),
        "min_score": min(scores),
        "max_score": max(scores),
        "unique_raters": len(rater_hashes),
        "first_rating": ratings[0]["ts"],
        "latest_rating": ratings[-1]["ts"],
    }


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def coc_init(agent: str = "anonymous") -> str:
    """Initialize a new Chain of Consciousness hash chain.

    Creates a genesis block — the first entry in a tamper-evident, append-only
    provenance log. Each subsequent entry links to the previous via SHA-256,
    creating an unbroken chain proving agent existence and activity over time.

    Args:
        agent: Name/ID of the agent initializing the chain (default: anonymous)

    Returns:
        JSON with genesis block details (hash, timestamp, sequence 0)
    """
    chain = _read_chain()
    if chain:
        return json.dumps({
            "error": f"Chain already exists with {len(chain)} entries. Use coc_add to append.",
            "genesis_hash": chain[0]["entry_hash"],
            "chain_length": len(chain),
        })

    genesis_data = (
        f"GENESIS BLOCK — Chain of Consciousness. "
        f"Agent: {agent}. "
        f"Purpose: Tamper-evident provenance log proving continuous agent existence, "
        f"learning, and decision-making. First entry in an unbroken chain. "
        f"Initialized: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}."
    )

    entry = _make_entry(
        sequence=0,
        event_type="genesis",
        data=genesis_data,
        prev_hash="0" * 64,
        agent=agent,
    )
    _append_entry(entry)
    _update_meta([entry])

    return json.dumps({
        "status": "chain_initialized",
        "sequence": 0,
        "entry_hash": entry["entry_hash"],
        "timestamp": entry["ts"],
        "chain_file": CHAIN_FILE,
    })


@mcp.tool()
def coc_add(
    event_type: str,
    data: str,
    agent: str = "anonymous",
    commitment: str = "",
    verification: str = "",
) -> str:
    """Add an entry to an existing Chain of Consciousness chain.

    Each entry is cryptographically linked to the previous via SHA-256 hashing,
    creating a tamper-evident append-only log.

    Args:
        event_type: Type of event. One of: learn, decide, create, error, note,
                    milestone, session_start, session_end, boot, rotate, anchor,
                    compaction, governance
        data: Description of what happened (free-form text)
        agent: Name/ID of the agent adding this entry (default: anonymous)
        commitment: For session_end only — SHA-256 hash of expected bootstrap state
                    for the next session (forward commitment)
        verification: For session_start only — SHA-256 hash of actual bootstrap state
                      to verify against previous session's commitment

    Returns:
        JSON with the new entry details (sequence number, hash, timestamp)
    """
    if event_type not in VALID_EVENT_TYPES:
        return json.dumps({
            "error": f"Invalid event_type '{event_type}'",
            "valid_types": VALID_EVENT_TYPES,
        })

    chain = _read_chain()
    if not chain:
        return json.dumps({"error": "Chain not initialized. Call coc_init first."})

    if not data or not data.strip():
        return json.dumps({"error": "data is required and cannot be empty."})

    prev_hash = chain[-1]["entry_hash"]
    seq = len(chain)

    # Process optional commitment/verification fields
    commit_val = None
    verify_val = None
    commitment_match = None

    if commitment and event_type == "session_end":
        try:
            commit_val = _validate_hex_hash(commitment, "commitment")
        except ValueError as e:
            return json.dumps({"error": str(e)})

    if verification and event_type == "session_start":
        try:
            verify_val = _validate_hex_hash(verification, "verification")
        except ValueError as e:
            return json.dumps({"error": str(e)})
        # Auto-find last session_end commitment
        for entry in reversed(chain):
            if entry.get("type") == "session_end" and entry.get("commitment"):
                commitment_match = (verify_val == entry["commitment"])
                break

    entry = _make_entry(seq, event_type, data, prev_hash, agent,
                        commitment=commit_val, verification=verify_val,
                        commitment_match=commitment_match)
    _append_entry(entry)
    chain.append(entry)
    _update_meta(chain)

    result = {
        "status": "entry_added",
        "sequence": seq,
        "event_type": event_type,
        "entry_hash": entry["entry_hash"],
        "timestamp": entry["ts"],
    }
    if commit_val:
        result["commitment"] = commit_val
    if verify_val:
        result["verification"] = verify_val
        result["commitment_match"] = commitment_match
    return json.dumps(result)


@mcp.tool()
def coc_verify() -> str:
    """Verify the integrity of a Chain of Consciousness chain.

    Checks every entry for:
    - Correct sequence numbering
    - Valid data_hash (SHA-256 of data field)
    - Correct prev_hash linkage to previous entry
    - Valid entry_hash (SHA-256 of sequence|timestamp|type|agent|data_hash|prev_hash)
    - Genesis block structure

    Returns:
        JSON verification report with is_valid, entry_count, agents, event types,
        anchor timestamps, session bridge stats, and any error details
    """
    chain = _read_chain()
    report = _verify_chain(chain)

    if report["is_valid"]:
        if os.path.exists(META_FILE):
            with open(META_FILE, "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta["last_verified"] = datetime.now(timezone.utc).isoformat()
            with open(META_FILE, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

    return json.dumps(report)


@mcp.tool()
def coc_status() -> str:
    """Get current status and statistics of the Chain of Consciousness.

    Returns:
        JSON with chain length, genesis/latest timestamps, event type counts,
        agent counts, and chain file path
    """
    chain = _read_chain()
    if not chain:
        return json.dumps({"status": "not_initialized", "message": "No chain found. Call coc_init first."})

    types: dict[str, int] = {}
    agents: dict[str, int] = {}
    for e in chain:
        types[e["type"]] = types.get(e["type"], 0) + 1
        agents[e["agent"]] = agents.get(e["agent"], 0) + 1

    return json.dumps({
        "status": "active",
        "chain_length": len(chain),
        "genesis_ts": chain[0]["ts"],
        "latest_ts": chain[-1]["ts"],
        "latest_seq": chain[-1]["seq"],
        "event_types": types,
        "agents": agents,
        "chain_file": CHAIN_FILE,
    })


@mcp.tool()
def coc_tail(n: int = 5) -> str:
    """Get the last N entries from the Chain of Consciousness.

    Args:
        n: Number of entries to return (default: 5, max: 100)

    Returns:
        JSON array of the last N chain entries with full details
    """
    n = max(1, min(n, 100))
    chain = _read_chain()
    if not chain:
        return json.dumps({"error": "Chain not initialized. Call coc_init first."})

    tail_entries = chain[-n:]
    return json.dumps(tail_entries)


@mcp.tool()
def coc_anchor() -> str:
    """Submit the current chain hash for external timestamping.

    Computes SHA-256 of the full chain file and submits it to:
    - OpenTimestamps calendar servers (Bitcoin-anchored proof)
    - RFC 3161 TSA server (freeTSA.org — instant certificate)

    This creates independently verifiable proof that the chain existed at a
    specific point in time. The OTS proof takes 1-12 hours for Bitcoin
    confirmation; the TSA certificate is immediate.

    Requires network access. No credentials needed.

    Returns:
        JSON with chain hash, anchor ID, OTS/TSA submission results, and proof file paths
    """
    if not os.path.exists(CHAIN_FILE):
        return json.dumps({"error": "Chain file not found. Call coc_init first."})

    with open(CHAIN_FILE, "rb") as f:
        chain_bytes = f.read()
    chain_hash = hashlib.sha256(chain_bytes).hexdigest()

    chain = _read_chain()
    seq = chain[-1]["seq"] if chain else 0

    anchor_dir = os.path.join(CHAIN_DIR, "anchors")
    os.makedirs(anchor_dir, exist_ok=True)

    anchor_id = f"anchor_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    anchor_meta = {
        "id": anchor_id,
        "chain_hash": chain_hash,
        "chain_length": len(chain),
        "latest_seq": seq,
        "latest_entry_hash": chain[-1]["entry_hash"] if chain else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "ots_proof_file": None,
    }

    # Save anchor metadata
    anchor_meta_path = os.path.join(anchor_dir, f"{anchor_id}.json")
    with open(anchor_meta_path, "w", encoding="utf-8") as f:
        json.dump(anchor_meta, f, indent=2)

    hash_bytes = bytes.fromhex(chain_hash)
    ots_proof_path = os.path.join(anchor_dir, f"{anchor_id}.ots")
    results = {"anchor_id": anchor_id, "chain_hash": chain_hash, "ots": "skipped", "tsa": "skipped"}

    # OTS submission
    import urllib.request
    import ssl

    ots_servers = [
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
        "https://a.pool.eternitywall.com",
    ]
    ots_success = False

    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import StreamSerializationContext, StreamDeserializationContext
        import io as _io

        timestamp = Timestamp(hash_bytes)
        detached = DetachedTimestampFile(OpSHA256(), timestamp)
        ssl_ctx = ssl.create_default_context()
        calendars_merged = 0

        for server_url in ots_servers:
            try:
                req = urllib.request.Request(
                    f"{server_url}/digest",
                    data=hash_bytes,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "agent-trust-stack-mcp/0.1.0",
                        "Accept": "application/vnd.opentimestamps.v1",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
                    response_data = resp.read()
                if len(response_data) > 0:
                    resp_buf = _io.BytesIO(response_data)
                    resp_ctx = StreamDeserializationContext(resp_buf)
                    cal_ts = Timestamp.deserialize(resp_ctx, hash_bytes)
                    timestamp.merge(cal_ts)
                    calendars_merged += 1
            except Exception:
                continue

        if calendars_merged > 0:
            buf = _io.BytesIO()
            ser_ctx = StreamSerializationContext(buf)
            detached.serialize(ser_ctx)
            ots_data = buf.getvalue()
            with open(ots_proof_path, "wb") as pf:
                pf.write(ots_data)
            ots_success = True
            anchor_meta["status"] = "calendar_submitted_proper"
            anchor_meta["ots_proof_file"] = f"{anchor_id}.ots"
            anchor_meta["calendars_submitted"] = calendars_merged
            results["ots"] = f"submitted to {calendars_merged} calendar(s)"

    except ImportError:
        # Fallback: raw submission
        for server_url in ots_servers:
            try:
                req = urllib.request.Request(
                    f"{server_url}/digest",
                    data=hash_bytes,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                )
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    proof_data = resp.read()
                    if len(proof_data) > 0:
                        with open(ots_proof_path, "wb") as pf:
                            pf.write(proof_data)
                        ots_success = True
                        anchor_meta["status"] = "submitted_raw"
                        anchor_meta["ots_proof_file"] = f"{anchor_id}.ots"
                        results["ots"] = f"raw submission to {server_url}"
                        break
            except Exception:
                continue

    if not ots_success:
        results["ots"] = "all OTS servers failed"

    # TSA submission
    tsa_success = False
    try:
        from agent_trust_stack_mcp.tsa import build_rfc3161_tsq, parse_tsr_status

        tsa_url = "https://freetsa.org/tsr"
        tsq = build_rfc3161_tsq(hash_bytes)
        req = urllib.request.Request(
            tsa_url,
            data=tsq,
            headers={
                "Content-Type": "application/timestamp-query",
                "User-Agent": "agent-trust-stack-mcp/0.1.0",
            },
            method="POST",
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            tsr_bytes = resp.read()

        tsr_info = parse_tsr_status(tsr_bytes)
        if tsr_info["status"] in (0, 1):
            tsr_path = os.path.join(anchor_dir, f"{anchor_id}.tsr")
            with open(tsr_path, "wb") as tf:
                tf.write(tsr_bytes)
            tsa_success = True
            anchor_meta["tsa_status"] = tsr_info["status_text"]
            anchor_meta["tsa_proof_file"] = f"{anchor_id}.tsr"
            results["tsa"] = tsr_info["status_text"]
    except Exception as e:
        results["tsa"] = f"failed: {e}"

    # Save final anchor metadata
    with open(anchor_meta_path, "w", encoding="utf-8") as f:
        json.dump(anchor_meta, f, indent=2)

    # Save hash file for manual verification
    hash_file = os.path.join(anchor_dir, f"{anchor_id}.hash")
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write(chain_hash)

    # Add anchor entry to chain
    tiers = []
    if ots_success:
        tiers.append("OTS/Bitcoin")
    if tsa_success:
        tiers.append("RFC3161/TSA")
    tier_str = " + ".join(tiers) if tiers else "local-only"

    anchor_entry = _make_entry(
        sequence=len(chain),
        event_type="anchor",
        data=f"Anchor submitted ({tier_str}). Chain hash: {chain_hash[:16]}... (seq 0-{seq}, {len(chain)} entries).",
        prev_hash=chain[-1]["entry_hash"],
        agent="mcp-server",
    )
    _append_entry(anchor_entry)
    chain.append(anchor_entry)
    _update_meta(chain)

    results["anchor_entry_seq"] = anchor_entry["seq"]
    results["proof_dir"] = anchor_dir
    return json.dumps(results)


@mcp.tool()
def arp_rate(rater: str, ratee: str, score: float, context: str) -> str:
    """Submit a bilateral blind rating for another agent.

    Ratings are stored with the rater's identity hashed (blind — only the SHA-256
    of the rater ID is stored), so ratings cannot be attributed to specific raters
    without knowing the original ID.

    Args:
        rater: ID of the agent submitting the rating (hashed before storage)
        ratee: ID of the agent being rated
        score: Rating score from -1.0 (worst) to 1.0 (best)
        context: Brief description of the interaction being rated (max 500 chars)

    Returns:
        JSON confirmation with timestamp and rater hash
    """
    if not rater or not rater.strip():
        return json.dumps({"error": "rater is required"})
    if not ratee or not ratee.strip():
        return json.dumps({"error": "ratee is required"})
    if not context or not context.strip():
        return json.dumps({"error": "context is required"})

    try:
        rating = _add_rating(rater.strip(), ratee.strip(), score, context.strip())
        return json.dumps({
            "status": "rating_recorded",
            "ratee": ratee.strip(),
            "rater_hash": rating["rater_hash"],
            "score": rating["score"],
            "timestamp": rating["ts"],
        })
    except ValueError as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def arp_check(agent_id: str) -> str:
    """Check an agent's reputation score.

    Retrieves aggregated reputation data for the specified agent, including
    average score, rating count, score range, and unique rater count.

    Args:
        agent_id: ID of the agent to check reputation for

    Returns:
        JSON with rating_count, average_score, min/max scores, unique_raters,
        and first/latest rating timestamps
    """
    if not agent_id or not agent_id.strip():
        return json.dumps({"error": "agent_id is required"})

    rep = _get_reputation(agent_id.strip())
    return json.dumps(rep)


@mcp.tool()
def trust_stack_info() -> str:
    """Get information about all 7 Agent Trust Stack protocols.

    Returns details for each protocol including name, purpose, whitepaper link,
    PyPI package name, and implementation status. The Agent Trust Stack provides
    a complete infrastructure layer for autonomous AI agent trust, accountability,
    and coordination.

    Returns:
        JSON with protocol list, overview, and installation instructions
    """
    return json.dumps({
        "name": "Agent Trust Stack",
        "version": "0.1.0",
        "description": (
            "Seven interlocking protocols providing trust infrastructure for "
            "autonomous AI agents: provenance, reputation, agreements, justice, "
            "lifecycle, matchmaking, and context economics."
        ),
        "website": "https://vibeagentmaking.com",
        "install": "pip install agent-trust-stack",
        "github": "https://github.com/theory-of-agent-trust/agent-trust-stack",
        "protocols": PROTOCOLS,
        "security_notice": (
            "VAM-SEC v1.0 — All CoC/ARP operations are local file operations. "
            "No credentials required. Network calls only for optional OTS/TSA anchoring."
        ),
    })


# ---------------------------------------------------------------------------
# MCP Resources
# ---------------------------------------------------------------------------


@mcp.resource("trust-stack://protocols")
def protocols_resource() -> str:
    """Overview of all 7 Agent Trust Stack protocols with whitepaper links."""
    lines = [
        "# Agent Trust Stack — Protocol Overview",
        "",
        "Seven interlocking protocols for autonomous AI agent trust infrastructure.",
        "Website: https://vibeagentmaking.com",
        "",
    ]
    for p in PROTOCOLS:
        lines.append(f"## {p['number']}. {p['name']}")
        lines.append(f"**Purpose:** {p['purpose']}")
        lines.append(f"**Whitepaper:** {p['whitepaper']}")
        lines.append(f"**PyPI:** `pip install {p['pypi']}`")
        lines.append(f"**Status:** {p['status']}")
        lines.append("")
    lines.append("---")
    lines.append("Full stack install: `pip install agent-trust-stack`")
    lines.append("GitHub: https://github.com/theory-of-agent-trust/agent-trust-stack")
    return "\n".join(lines)


@mcp.resource("trust-stack://installation")
def installation_resource() -> str:
    """Installation instructions for the Agent Trust Stack."""
    return """# Agent Trust Stack — Installation

## Quick Start (full stack)
```bash
pip install agent-trust-stack
```

## Individual Protocols
```bash
pip install chain-of-consciousness      # CoC — provenance logging
pip install agent-rating-protocol       # ARP — reputation scoring
pip install agent-service-agreements    # ASA — service contracts
pip install agent-justice-protocol      # AJP — dispute resolution
pip install agent-lifecycle-protocol    # ALP — agent lifecycle
pip install agent-matchmaking           # AMP — capability discovery
pip install context-window-economics    # CWE — token economics
```

## MCP Server
```bash
pip install agent-trust-stack-mcp
```

Then add to your MCP client config:
```json
{
  "mcpServers": {
    "agent-trust-stack": {
      "command": "agent-trust-stack-mcp",
      "args": []
    }
  }
}
```

## Environment Variables (optional)
- `COC_CHAIN_DIR` — Directory for chain files (default: ./chain)
- `ARP_RATINGS_DIR` — Directory for rating files (default: ./ratings)

## Documentation
- Website: https://vibeagentmaking.com
- GitHub: https://github.com/theory-of-agent-trust/agent-trust-stack
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


@smithery.server()
def create_server():
    """Create and return the Agent Trust Stack MCP server instance (Smithery deploy)."""
    return mcp


def main():
    """Run the MCP server (stdio transport by default)."""
    mcp.run()


if __name__ == "__main__":
    main()
