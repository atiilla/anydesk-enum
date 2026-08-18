# AnyDesk ID Enumeration & Info Disclosure

AnyDesk clients are identified by 9-10 digit numeric IDs. The relay infrastructure leaks information about any ID during the connection handshake, before authentication. The target gets no notification.

All you need is an AnyDesk installation.

## What leaks

| Data | When |
|---|---|
| ID valid or not | Always |
| Online / offline | Always |
| Fingerprint (short + full 40-char) | Valid IDs |
| Public IP + port | Online targets |
| Relay server | Online targets |
| Internal/private IPs (LAN, Docker, VPN) | Online targets |

The internal IP leak is the worst part it exposes the target's network topology to anyone who knows their ID.

## Why enumeration works

AnyDesk IDs are short numeric values (9-10 digits) with no secret component. They're guessable you don't need to know a target's ID to find valid ones. The relay tells you whether any given ID exists or not, creating an oracle: try random numbers, keep the ones that return a fingerprint, discard the rest.

At ~250ms per lookup, an attacker can validate thousands of IDs per hour. The ID space is large (~10 billion) but AnyDesk has 500M+ downloads, so a significant portion of the range is allocated. There's no rate limiting on the relay side.

## How it works

1. Send a connection request to the relay for a target ID
2. Relay responds with status, fingerprint, IP, relay **before auth**
3. Target sees nothing
4. Parse `ad.trace` where AnyDesk logs the response

Relay response time: **~250ms**.

[![asciicast](https://asciinema.org/a/QCrSEcNAkFHcwMDk.svg)](https://asciinema.org/a/QCrSEcNAkFHcwMDk)

### Trace output (lab)

```
anynet.any_socket - Client-ID: <target> (FPR: <fingerprint>).
anynet.any_socket - Logged in from <public-ip>:<port> on relay <relay-id>.
anynet.connection_mgr - Making a new connection to client <full-fingerprint>.
anynet.punch_connector - -> Spawning: <lan-ip>:7070
anynet.punch_connector - -> Spawning: <docker-ip>:7070
anynet.punch_connector - -> Spawning: <link-local-ip>:7070
```

### Output: 
```json
{
  "timestamp": "2026-08-16T14:28:37.407584+00:00",
  "local_id": "<lab-machine-1>",
  "total_probed": 1,
  "valid_count": 1,
  "invalid_count": 0,
  "online_count": 1,
  "ip_leaked_count": 1,
  "results": [
    {
      "target_id": "<lab-machine-2>",
      "valid": true,
      "online": true,
      "client_id": "<lab-machine-2>",
      "fingerprint": "<redacted-fpr>",
      "source_ip": "<redacted-public-ip>:<port>",
      "relay_id": "<relay-id>",
      "remote_os": null,
      "remote_version": null,
      "status_text": null
    }
  ]
}

```

## Usage

Requires AnyDesk installed. On Linux, needs an X display.

```bash
python3 anydesk_id_enum.py info
python3 anydesk_id_enum.py probe --ids <your-lab-id>
python3 anydesk_id_enum.py probe --ids <your-lab-id> --wait 10 -o results.json

# from SSH
DISPLAY=:1 python3 anydesk_id_enum.py probe --ids <your-lab-id>
```

## Tested on

- Linux (AnyDesk 8.0.4)
- Windows (hidden window mode)

## Mitigations

- AnyDesk ACL / whitelist
- Enterprise namespace (custom IDs)
- Firewall AnyDesk relay traffic when not in use
- Disable the service when not needed
- Monitor `ad.trace` for recon

## Disclaimer

For authorized security research only. Don't enumerate IDs you don't own. All testing done on researcher-owned lab machines.

## Disclosure

- 2026-08-16: Discovered, documented, and published
- This is a design-level issue in the relay protocol, not a code bug
