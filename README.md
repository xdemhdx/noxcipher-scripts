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

> The catalogue on the site is currently placeholder data. A command only works once the matching script file is committed here.

**Read before you run.** Piping a script into a shell runs it with your permissions. Use the site's *Inspect first* mode, and pin a commit hash for production use.

## License

MIT
