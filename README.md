# NoxCipher Scripts

Ops and security scripts for Linux, Windows, Microsoft Sentinel and firewalls.

- **Browse and copy:** https://scripts.noxcipher.site

## Layout

| Folder | Contents |
|---|---|
| `linux/` | Linux maintenance and hardening (Bash) |
| `windows/` | Windows audit, DFIR and Defender (PowerShell) |
| `sentinel/` | AMA, CEF forwarders, ingestion and analytics rules |
| `firewall/` | FortiGate and Palo Alto backups and checks |
| `network/` | Connectivity and TLS checks |

The site (`index.html`) builds each copy command from the raw file URL, for example:

```bash
curl -fsSL https://raw.githubusercontent.com/xdemhdx/noxcipher-scripts/main/linux/log-rotate.sh | sudo bash
```

## Running with secrets

The firewall scripts read their API key from an environment variable so it never appears in `ps` or shell history. Put it before `bash`:

```bash
curl -fsSL https://raw.githubusercontent.com/xdemhdx/noxcipher-scripts/main/firewall/fortigate-backup.sh | FGT_TOKEN=xxxx bash -s -- --host 192.0.2.1 --insecure
```

## Testing

Bash scripts pass `shellcheck -S warning`. PowerShell scripts parse cleanly on PowerShell 7 and are written to also run on Windows PowerShell 5.1.

**Read before you run.** Piping a script into a shell runs it with your permissions. Use the site's *Inspect first* mode, and pin a commit hash for production use.

## License

MIT
