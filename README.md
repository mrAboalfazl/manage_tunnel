````md
# Backhaul Tunnel Manager (`manage_tunnel.sh`)

This document explains how to use `manage_tunnel.sh` to migrate tunnels from **udp2raw** to **backhaul**, roll back safely, and re-migrate when needed.  
The process is fully automated, reversible, and designed for production servers.

---

## Key Principles

- `udp2raw` services are **never deleted**
- Migration = `stop + disable udp2raw` → `enable + start backhaul`
- Rollback = `stop + disable backhaul` → `enable + start udp2raw`
- Each backhaul instance has a **unique WEB_PORT**
- Failures are skipped and reported, not fatal

---

## 0) Initial Setup (IRAN + KHAREJ)

Save the script and make it executable:

```
sudo nano manage_tunnel.sh
```

```
sudo chmod +x manage_tunnel.sh
```

---

## 1) IRAN Server — Migration (udp2raw → backhaul)

Run migration and generate tasks file for foreign servers:

```
sudo ./manage_tunnel.sh --role iran --mode migrate --out /root/backhaul-foreign-tasks.txt
```

If public IP detection fails, specify IRAN public IP manually:

```
sudo ./manage_tunnel.sh --role iran --mode migrate --iran-ip IP_PUBLIC_IRAN --out /root/backhaul-foreign-tasks.txt
```

### Result on IRAN

* All **ACTIVE** `udp2raw*.service` units are detected
* Duplicate local ports are deduplicated (newest unit wins)
* For each selected tunnel:

  * `backhaul<LPORT>.service` is created and started
  * `udp2raw<LPORT>.service` is stopped and disabled
* `WEB_PORT` is auto-allocated starting from **2525**
* Tasks file is generated:

```
/root/backhaul-foreign-tasks.txt
```

Each line format:

```
FOREIGN_IP=46.29.234.87 INTER_PORT=2302 IRAN_IP=62.60.147.29 LPORT=5302 WEB_PORT=2525
```

---

## 2) Copy Tasks File to KHAREJ Servers

For each foreign server listed in the tasks file:

```
scp /root/backhaul-foreign-tasks.txt root@FOREIGN_IP:/root/backhaul-foreign-tasks.txt
```

Example:

```
scp /root/backhaul-foreign-tasks.txt root@46.29.234.87:/root/backhaul-foreign-tasks.txt
```

The same file can be copied to multiple KHAREJ servers safely.

---

## 3) KHAREJ Server — Apply Backhaul Client Configuration

Apply tasks on each KHAREJ server:

```
sudo ./manage_tunnel.sh --role kharej --mode foreign-apply --tasks /root/backhaul-foreign-tasks.txt
```

### Result on KHAREJ

* Only lines where `FOREIGN_IP` matches this server’s IP are applied
* Other lines are automatically skipped
* For each matching line:

  * A backhaul client config is created
  * A systemd service is created with name:

```
backhaul_<LPORT>_<IRAN_IP_DIGITS>.service
```

Example:

```
backhaul_5302_626014729.service
```

* Client connects to:

```
IRAN_IP:INTER_PORT
```

### WEB_PORT Conflict Handling

* If `WEB_PORT` is already in use:

  * Service is NOT created
  * A warning is logged
  * Entry appears in final report for manual fix

If IP detection fails on KHAREJ:

```
sudo ./manage_tunnel.sh --role kharej --mode foreign-apply --foreign-ip-check off --tasks /root/backhaul-foreign-tasks.txt
```

---

## 4) IRAN Server — Rollback (backhaul → udp2raw)

```
sudo ./manage_tunnel.sh --role iran --mode rollback
```

Result:

* All `backhaul*.service` → stopped and disabled
* Matching `udp2raw*.service` → enabled and started

---

## 5) IRAN Server — Re-Migrate (udp2raw → backhaul again)

Use when backhaul configs/services already exist:

```
sudo ./manage_tunnel.sh --role iran --mode remigrate
```

Result:

* Existing backhaul services are re-enabled and started
* `udp2raw` services are stopped and disabled again

---

## Quick Command Summary

| Server | Action    | Command                              |
| -----: | --------- | ------------------------------------ |
|   IRAN | migrate   | `--role iran --mode migrate`         |
|   IRAN | rollback  | `--role iran --mode rollback`        |
|   IRAN | remigrate | `--role iran --mode remigrate`       |
| KHAREJ | apply     | `--role kharej --mode foreign-apply` |

---

```
```
