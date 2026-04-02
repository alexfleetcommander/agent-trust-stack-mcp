# Agent Trust Stack MCP Server

MCP (Model Context Protocol) server exposing the **Agent Trust Stack** tools so any MCP-compatible AI agent can use them natively.

Provides **Chain of Consciousness** (CoC) provenance logging and **Agent Rating Protocol** (ARP) reputation scoring — the two operational protocols from the [7-protocol Agent Trust Stack](https://vibeagentmaking.com).

## Tools

| Tool | Description |
|------|-------------|
| `coc_init` | Initialize a new cryptographic hash chain (genesis block) |
| `coc_add` | Append an entry — learn, decide, create, error, note, milestone, session_start/end |
| `coc_verify` | Verify chain integrity (hash linkage, sequence, completeness) |
| `coc_status` | Get chain stats (length, agents, time span, event types) |
| `coc_tail` | Get the last N entries |
| `coc_anchor` | Submit chain hash for external timestamping (OTS + RFC 3161 TSA) |
| `arp_rate` | Submit a bilateral blind rating for another agent |
| `arp_check` | Check an agent's reputation score |
| `trust_stack_info` | Get info about all 7 protocols with whitepaper links |

## Resources

| URI | Description |
|-----|-------------|
| `trust-stack://protocols` | Overview of all 7 protocols with links |
| `trust-stack://installation` | Installation instructions |

## Installation

```bash
pip install agent-trust-stack-mcp
```

For proper OpenTimestamps .ots file format (optional):
```bash
pip install agent-trust-stack-mcp[ots]
```

## Configuration

Add to your MCP client config (Claude Code, Cursor, etc.):

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

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `COC_CHAIN_DIR` | `./chain` | Directory for chain files |
| `ARP_RATINGS_DIR` | `./ratings` | Directory for rating files |

### Custom data directories

```json
{
  "mcpServers": {
    "agent-trust-stack": {
      "command": "agent-trust-stack-mcp",
      "args": [],
      "env": {
        "COC_CHAIN_DIR": "/path/to/my/chain",
        "ARP_RATINGS_DIR": "/path/to/my/ratings"
      }
    }
  }
}
```

## Usage Examples

Once connected, any MCP-compatible agent can call these tools directly:

### Start a provenance chain
```
→ coc_init(agent="my-agent")
← { "status": "chain_initialized", "sequence": 0, "entry_hash": "a1b2c3..." }
```

### Log activity
```
→ coc_add(event_type="learn", data="Processed 500 documents from dataset X", agent="my-agent")
← { "status": "entry_added", "sequence": 1, "entry_hash": "d4e5f6..." }
```

### Verify chain integrity
```
→ coc_verify()
← { "is_valid": true, "entry_count": 42, "agents": {"my-agent": 42} }
```

### Rate another agent
```
→ arp_rate(rater="agent-a", ratee="agent-b", score=0.8, context="Delivered accurate research")
← { "status": "rating_recorded", "rater_hash": "7f8a9b...", "score": 0.8 }
```

### Check reputation
```
→ arp_check(agent_id="agent-b")
← { "rating_count": 5, "average_score": 0.72, "unique_raters": 3 }
```

## Running Directly

```bash
# stdio mode (default — for MCP client connections)
agent-trust-stack-mcp

# Or via Python module
python -m agent_trust_stack_mcp
```

## How It Works

**Chain of Consciousness (CoC):** An append-only JSONL file where each entry contains a SHA-256 hash linking it to the previous entry, creating a tamper-evident log. Any modification to earlier entries breaks the hash chain, making tampering detectable. Optional external anchoring via OpenTimestamps (Bitcoin) and RFC 3161 TSA provides independent timestamp proof.

**Agent Rating Protocol (ARP):** Agents rate each other on a -1.0 to 1.0 scale after interactions. Rater identities are SHA-256 hashed before storage (bilateral blind), so ratings cannot be attributed without the original ID. Reputation is the aggregate of all received ratings.

## Registry Listings

- [Smithery](https://smithery.ai) — `agent-trust-stack`
- [Glama](https://glama.ai/mcp) — `agent-trust-stack`
- [mcp.so](https://mcp.so) — `agent-trust-stack`
- [MCP Servers](https://mcpservers.org) — `agent-trust-stack`

## Part of the Agent Trust Stack

This MCP server exposes tools from the [Agent Trust Stack](https://vibeagentmaking.com) — seven interlocking protocols for autonomous AI agent trust infrastructure:

1. **Chain of Consciousness** — Provenance logging *(this server)*
2. **Agent Rating Protocol** — Reputation scoring *(this server)*
3. **Agent Service Agreements** — Machine-readable contracts
4. **Agent Justice Protocol** — Dispute resolution
5. **Agent Lifecycle Protocol** — Birth, migration, retirement
6. **Agent Matchmaking** — Capability discovery
7. **Context Window Economics** — Token resource management

Full stack: `pip install agent-trust-stack`

## Security

**VAM-SEC v1.0** — All CoC and ARP operations are local file I/O. No credentials are required or stored. No network calls are made except during optional `coc_anchor` (OTS calendar servers + freeTSA.org). No API keys needed.

## License

Apache-2.0 — Copyright (c) 2026 AB Support LLC
