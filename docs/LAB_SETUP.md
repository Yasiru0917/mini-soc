# Lab Setup: VirtualBox Network and Wazuh VM

All scanning and monitoring in Mini SOC targets this isolated lab, not your home network or the internet.

## 1. Host resources (measured 2026-11-25)

| Resource | Available |
|---|---|
| CPU | Intel i7-13700H, 20 logical processors |
| RAM | 15.6 GB |
| Disk C: | **8.2 GB free** (too little for VMs) |
| Disk D: | 62.6 GB free |
| VirtualBox | 7.2.20 |
| Host-only adapter | `VirtualBox Host-Only Ethernet Adapter`, `192.168.56.1/255.255.255.0` (already exists) |
| Hypervisor | Hyper-V is active (`HypervisorPresent = True`) |

## 2. Wazuh requirements (official documentation)

Source: [Wazuh virtual machine (OVA)](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html) and [Quickstart](https://documentation.wazuh.com/current/quickstart.html), checked 2026-11-25 (Wazuh 4.14.10).

- The OVA contains the Wazuh manager, indexer and dashboard (all-in-one) on Amazon Linux 2023.
- It's **preconfigured with 4 CPU cores, 8 GB RAM and 50 GB of storage**.
- The host must be 64-bit x86_64 with hardware virtualization enabled.
- Quickstart recommendation for **1–25 agents: 4 vCPU, 8 GiB RAM, 50 GB disk** (sized for 90 days of indexed alerts).
- A Wazuh agent uses about 35 MB RAM on average.

## 3. Resource allocation decision

| VM | vCPU | RAM | Disk | When running |
|---|---|---|---|---|
| Wazuh OVA | 4 | **8 GB** (keep the official value) | 50 GB dynamic, **on D:** | Only during Phase 7 work and demos |
| Target VM (for example Metasploitable 2) | 1 | 512 MB – 1 GB | ~8 GB, on D: | During scanning practice (Phase 5) |
| Windows host + VS Code + browser + dev servers | the rest | ~6–7 GB | n/a | Always |

Why:

- **8 GB for Wazuh, not less.** The indexer (OpenSearch) is the heaviest part. The official value is already the documented recommendation for small labs, and going below it isn't supported. With 15.6 GB in total, that leaves about 7 GB for Windows and development. That's workable, but close other heavy apps while Wazuh is running.
- **4 vCPU out of 20** has no meaningful impact on the host.
- **The disk must be on D:.** C: has only 8.2 GB free, and VirtualBox would store VMs on C: by default. The disk is dynamically allocated, so it starts smaller and grows towards 50 GB as alerts are indexed. D: has 62.6 GB free, so check the free space now and then.
- Don't run every VM at once unless you need to. The Wazuh VM only has to run when you're working on Phase 7.

## 4. Setup steps (Phase 7, when we get there)

1. **Store VMs on D:.** In VirtualBox, open *File → Preferences → General → Default Machine Folder* and set it to `D:\VirtualBox VMs`.
2. **Download the OVA** from the official Wazuh page above. Don't use third-party mirrors. Verify the checksum if one is published.
3. **Import** it with *File → Import Appliance*. Keep 4 CPU and 8192 MB RAM.
4. **VirtualBox settings recommended by Wazuh:**
   - *Display → Graphics Controller:* **VMSVGA** (other controllers can freeze the VM window).
   - *System → Motherboard:* enable **Hardware Clock in UTC Time**.
5. **Network (important for security).**
   - The OVA defaults to a **Bridged** adapter, which would put the VM on your home network while it still has its default passwords.
   - Change it to:
     - *Adapter 1:* **Host-only Adapter** → `VirtualBox Host-Only Ethernet Adapter` (192.168.56.0/24)
     - *Adapter 2:* **NAT**, only if the VM needs internet access for updates
6. **Change the default credentials immediately.**
   - Every copy of the OVA ships with the same defaults (VM user `wazuh-user`, dashboard `admin`). Wazuh's documentation strongly recommends changing them on first access.
   - Store the new API credentials only in `backend/.env`, never in code.
7. Find the VM's IP with `ip addr`. Expect something like `192.168.56.10x`. Then open `https://<VM-IP>` from Windows.

Wazuh's default ports, which the integration will use:

| Port | Use |
|---|---|
| 443 | Dashboard |
| 55000 | Server API |
| 9200 | Indexer |
| 1514 / 1515 | Agent connection and enrollment |

Confirm these on your VM; they weren't stated on the pages checked above.

## 5. Hyper-V note

Hyper-V is active on this machine. That's common when WSL2, Memory Integrity or Windows Sandbox are enabled. VirtualBox 7 can run on top of Hyper-V, but VMs may be slower; a green turtle icon in the VM status bar shows this mode.

Try it first. If performance is unusable, the alternative is turning Hyper-V off, but that also disables WSL2 and Windows security features such as Memory Integrity. That's a trade-off to decide deliberately, not by default.

## 6. Authorized scanning scope

- Default allowed scope: **`192.168.56.0/24`** (host-only network, reachable only from this PC and its VMs).
- `192.168.56.1` is the Windows host itself.
- Never scan your home LAN, a work or university network, or internet hosts without written permission. Mini SOC will refuse out-of-scope targets (Phase 5).
