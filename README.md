```
 ███████╗███████╗██████╗  ██████╗ ███████╗██╗   ██╗███╗   ███╗
 ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║████╗ ████║
   ███╔╝ █████╗  ██████╔╝██║   ██║███████╗██║   ██║██╔████╔██║
  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════██║██║   ██║██║╚██╔╝██║
 ███████╗███████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║ ╚═╝ ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝
```
**Friend-to-friend encrypted messaging over Tor. Single server. Zero trust. Zero trace.**

---

## What is ZeroSum?

ZeroSum is a private messaging system designed for exactly two people. You run the server yourself — it spins up its own Tor hidden service automatically (no separate `tor` binary needed) — and your friend connects to the `.onion` address. The server sees nothing it doesn't already know, because it's *your* server.

**The core promise:** if someone seizes your machine, they get nothing. If someone watches the wire, they see nothing. If someone compromises the server process, they learn nothing they didn't already know.

## What's New in v2 (vs. the original)

Every shortcoming from the security audit has been addressed:

| Original Problem | v2 Fix |
|---|---|
| `stealth.rs` was a no-op placeholder | Real process cloaking: `prctl(PR_SET_NAME)`, core dump disable, `MADV_DONTDUMP` |
| In-memory Signal store (lost on crash) | Encrypted persistent session store (`sessions.enc`) with version detection |
| No key fingerprint verification (MITM blind spot) | Signal-style safety numbers: `/verify` command, 60-digit fingerprint |
| `contacts.txt` in plaintext (social graph on disk) | Encrypted contact store (`contacts.enc`), XChaCha20-Poly1305 |
| Duplicate protocol module (desync risk) | **Single** canonical `protocol/` crate — client imports it directly |
| External `tor` process required + ngrok tunneling | **Embedded Arti** — single binary, self-contained Tor hidden service |
| C FFI to `libsignal-protocol-c` (memory safety risk) | Pure Rust crypto: X3DH + Double Ratchet, no C dependencies |
| No message padding (traffic analysis) | Fixed 512-byte block padding on all messages |
| No heartbeat jitter (timing fingerprint) | Randomized heartbeat intervals (30s ± 0-5s jitter) |
| No wire protocol versioning | Version byte in every frame — mismatch = explicit rejection |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     WORKSPACE                             │
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │  protocol/   │  │   crypto/    │  │      tor/       │ │
│  │  wire format │  │ X3DH,ratchet │  │  embedded arti  │ │
│  │  framing     │  │ identity     │  │  SOCKS fallback │ │
│  │  padding     │  │ fingerprints │  │  hidden service │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬──────────┘ │
│         │                 │                  │            │
│  ┌──────┴─────────────────┴──────────────────┴─────────┐ │
│  │                    server/                           │ │
│  │  SQLite directory · message queue · presence         │ │
│  │  Tor hidden service auto-start                       │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │                    client/                           │ │
│  │  ratatui TUI · E2EE messaging · encrypted history   │ │
│  │  contacts · stealth · panic purge · file sharing    │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

5 crates, 1 protocol source of truth, 0 C dependencies.

## Quick Start

### Prerequisites

- Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- That's it. No CMake, no C compiler, no separate Tor installation.

### Build

```bash
git clone https://github.com/yourname/zerosum.git
cd zerosum
cargo build --release
```

Binaries land in `target/release/`:
- `zerosum-server` — the relay server
- `zerosum-client` — the TUI client

### Run the Server

```bash
# With embedded Tor (default — generates a .onion address automatically):
./target/release/zerosum-server

# Local testing only (no Tor):
ZEROSUM_NO_TOR=1 ./target/release/zerosum-server
```

The server prints your `.onion` address. Share it with your friend over a separate secure channel.

### Run the Client

```bash
# Connect to an onion address:
./target/release/zerosum-client --server <address>.onion

# Local testing:
./target/release/zerosum-client --server 127.0.0.1:18080 --no-tor
```

### Android (Termux)

```bash
pkg install rust
git clone https://github.com/yourname/zerosum.git
cd zerosum
cargo build --release
./target/release/zerosum-client --server <address>.onion
```

## Commands

| Command | Description |
|---|---|
| `/select <user>` | Select a contact to chat with |
| `/add <user>` | Add a contact |
| `/remove <user>` | Remove a contact |
| `/alias <user> <name>` | Set a display name |
| `/verify [user]` | Show safety number for key verification |
| `/file <path>` | Send an encrypted file |
| `/contacts` | List all contacts |
| `/history on\|off` | Toggle local encrypted history |
| `/purge` | Securely delete history file |
| `/clear` | Clear chat display |
| `/status` | Show connection info |
| `/lock` | Lock screen |
| `/help` | Show all commands |
| `/quit` | Exit |
| `!panic` | **⚠ DESTROY ALL LOCAL DATA** |

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Tab` | Cycle through contacts |
| `Esc` | Deselect contact (show system log) |
| `F1` / `Ctrl+H` | Toggle help overlay |
| `Ctrl+C` | Quit |
| `↑/↓` | Input history |

## Security Model

### What the server knows
- Usernames and password hashes (your server, your data)
- Encrypted ciphertext blobs it can't decrypt
- Who is online (presence)
- That's it.

### What the server never sees
- Message plaintext
- Contact lists
- Chat history
- Identity private keys

### Cryptographic stack
- **Identity keys:** Ed25519 (signing) + X25519 (key agreement)
- **Key exchange:** X3DH (Extended Triple Diffie-Hellman)
- **Message encryption:** Double Ratchet → XChaCha20-Poly1305
- **Key derivation:** HKDF-SHA256
- **Password protection:** Argon2id
- **Local encryption:** XChaCha20-Poly1305
- **All keys zeroized** on drop via the `zeroize` crate

### Anti-forensics
- `!panic` command: 3-pass secure wipe of all local files
- No plaintext ever touches disk (contacts, sessions, history — all encrypted)
- Process name cloaking on Linux (`prctl`)
- Core dumps disabled
- Sensitive memory regions `mlock`'d (never swapped)

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ZEROSUM_SERVER_ADDR` | — | Server address (onion or host:port) |
| `ZEROSUM_SOCKS_ADDR` | `127.0.0.1:9050` | SOCKS proxy for Tor fallback |
| `ZEROSUM_NO_TOR` | unset | Set to `1` to disable Tor |
| `ZEROSUM_PORT` | `18080` | Server bind port |
| `ZEROSUM_DATA_DIR` | platform default | Data directory |
| `RUST_LOG` | `info` | Tracing log level |

## Cross-Platform

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | ✅ Full support | All features including process stealth |
| Windows | ✅ Full support | Console title renaming for stealth |
| Android (Termux) | ✅ Works | Install Rust via Termux; full TUI |
| macOS | ✅ Should work | Untested but no platform-specific deps |

## License

MIT
