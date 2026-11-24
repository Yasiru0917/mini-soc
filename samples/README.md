# Sample files (synthetic)

These files are hand-made examples for trying the Log Analysis module. They are **not real attack data**.

- Attacker addresses come from the RFC 5737 *documentation* ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). These are reserved for examples and never belong to real hosts.
- Lab hosts use the VirtualBox host-only range `192.168.56.0/24`.

When you upload them, the detection rules really run and raise alerts. The *detection* is genuine (rule logic applied to the file); the *input* is synthetic. Each alert records the file name and SHA-256 it came from, so you can always trace that.

| File | Format | Should trigger |
|---|---|---|
| `sample-auth.log` | Linux auth.log | R-001 SSH brute force, R-002 login after brute force |
| `sample-access.log` | Apache/Nginx combined | R-003 path traversal, R-004 SQL injection, R-005 404 enumeration |
| `sample-events.jsonl` | JSON lines | R-001 SSH brute force |
| `sample-portscan.pcap` | pcap | R-006 port scan (create it with `python -m scripts.make_sample_pcap` from `backend/`) |

## Producing real data in your lab

To see genuine detections, generate traffic inside the host-only lab, only against your own VMs:

- **SSH brute force:** from one lab VM, run `hydra -l root -P small-wordlist.txt ssh://192.168.56.101` against a Metasploitable VM, then copy `/var/log/auth.log` from the target.
- **Web scanning:** run `nikto -h http://192.168.56.101` and copy the web server's `access.log`.
- **Packet capture:** in Wireshark, capture on the *VirtualBox Host-Only* adapter while running an Nmap scan of a lab VM, then save as `.pcap`.
