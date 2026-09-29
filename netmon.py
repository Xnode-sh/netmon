#!/usr/bin/env python3
"""netmon - мониторинг локальной сети: устройства, трафик, DNS, pcap, роутер.

Подкоманды:
  env                     показать окружение (интерфейс, шлюз, подсеть, DNS)
  discover                инвентаризация устройств в подсети + история в БД
  dns start|stop|status   логирование DNS-запросов этого хоста (ETW)
  dns top [N]             топ доменов из лога
  traffic --seconds N     учёт трафика по устройствам (pktmon)
  pcap start|stop         захват пакетов в pcapng (для Wireshark)
  router CMD              выполнить команду в telnet-шелле роутера
  watch --seconds N       опрос роутера: ARP + conntrack + счётчики интерфейсов
  report                  сводка по всем данным
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import ipaddress
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

from oui import OuiDb

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
LOGS = BASE / "logs"
CAPS = BASE / "captures"
DB_PATH = DATA / "netmon.db"
OUI = OuiDb(DATA / "oui.txt")

DNS_CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
DNS_CSV = LOGS / "dns_log.csv"
DNS_TAIL_PS1 = BASE / "dns_tail.ps1"
DNS_PID = LOGS / "dns_tail.pid"

PS_PKTMON = r"$ErrorActionPreference='Stop'; try { (Invoke-Command -ScriptBlock { $OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8 } -NoNewScope) } catch {}; chcp 65001 > $null; "


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def run(cmd, timeout=60, shell=False, check=False):
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        shell=shell, check=check, encoding="utf-8", errors="replace",
    )


def pktmon(*args, timeout=300):
    return run([r"C:\Windows\System32\PktMon.exe", *args], timeout=timeout)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin(what: str) -> None:
    if not is_admin():
        sys.exit(f"[!] {what} требует прав администратора. Запусти PowerShell/cmd от имени администратора.")


def ensure_dirs() -> None:
    for d in (DATA, LOGS, CAPS):
        d.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    ensure_dirs()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices(
            ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, hostname TEXT,
            nbname TEXT, first_seen TEXT, last_seen TEXT,
            is_gateway INTEGER DEFAULT 0, source TEXT,
            state TEXT, online INTEGER DEFAULT 0, last_alive TEXT
        );
        CREATE TABLE IF NOT EXISTS dns(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, event INTEGER,
            domain TEXT, qtype TEXT, server TEXT, rcode TEXT, answers TEXT
        );
        CREATE TABLE IF NOT EXISTS pairs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_ts TEXT, ip TEXT,
            peer TEXT, proto TEXT, port INTEGER,
            rx_bytes INTEGER DEFAULT 0, tx_bytes INTEGER DEFAULT 0,
            rx_pkts INTEGER DEFAULT 0, tx_pkts INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS flows(
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_ts TEXT, local_ip TEXT,
            local_port INTEGER, remote_ip TEXT, remote_port INTEGER,
            proto TEXT, state TEXT, src TEXT
        );
        CREATE TABLE IF NOT EXISTS iface(
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_ts TEXT, iface TEXT,
            rx_bytes INTEGER, tx_bytes INTEGER
        );
        CREATE INDEX IF NOT EXISTS ix_dns_ts ON dns(ts);
        CREATE INDEX IF NOT EXISTS ix_pairs_run ON pairs(run_ts);
        CREATE INDEX IF NOT EXISTS ix_flows_run ON flows(run_ts);
        CREATE TABLE IF NOT EXISTS imports(
            name TEXT PRIMARY KEY, bytes INTEGER, rows INTEGER
        );
        """
    )
    con.commit()
    return con


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


# ---------------------------------------------------------------- network env

def local_network() -> dict:
    ps = (
        "$c = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } "
        "| Select-Object -First 1; if ($c) { [pscustomobject]@{"
        "ip=$c.IPv4Address.IPAddress; prefix=$c.IPv4Address.PrefixLength; "
        "gw=$c.IPv4DefaultGateway.NextHop; dns=($c.DNSServer.ServerAddresses -join ','); "
        "iface=$c.InterfaceAlias; mac=$c.NetAdapter.MacAddress } | ConvertTo-Json -Compress }"
    )
    r = run(["powershell", "-NoProfile", "-Command", ps], timeout=30)
    text = (r.stdout or "").strip()
    if not text:
        sys.exit("[!] Не удалось определить сеть: нет активного адаптера с шлюзом.")
    d = json.loads(text)
    d["prefix"] = int(d.get("prefix") or 24)
    d["dns"] = [x for x in (d.get("dns") or "").split(",") if x and x != "0.0.0.0"]
    return d


def subnet_ips(ip: str, prefix: int) -> list[str]:
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    if net.num_addresses > 1024:
        sys.exit(f"[!] Сеть {net} слишком велика для быстрого сканирования. Укажи /24 или уже.")
    return [str(h) for h in net.hosts()]


def own_macs() -> set[str]:
    out: set[str] = set()
    try:
        r = run(["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Where-Object {$_.MacAddress} | ForEach-Object {$_.MacAddress}"])
        for m in re.findall(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", r.stdout or ""):
            out.add(m.lower())
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ discovery

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def mac_kind(mac: str) -> str:
    if not mac or not MAC_RE.match(mac):
        return ""
    first = int(mac[:2], 16)
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    if first & 0x01:
        return "multicast/broadcast (неunicast)"
    if first & 0x02:
        return "locally administered (приватный MAC устройства)"
    return ""


def neighbor_map() -> dict[str, tuple[str, str]]:
    ps = (
        "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.LinkLayerAddress -and $_.IPAddress -notmatch '^(224|239|255)\\.' } | "
        "ForEach-Object { \"$($_.IPAddress)|$($_.LinkLayerAddress)|$($_.State)\" }"
    )
    r = run(["powershell", "-NoProfile", "-Command", ps], timeout=90)
    out: dict[str, tuple[str, str]] = {}
    for line in (r.stdout or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        ip, mac, state = parts[0].strip(), parts[1].strip().replace("-", ":").lower(), parts[2].strip()
        if MAC_RE.match(mac) and mac != "00:00:00:00:00:00":
            out[ip] = (mac, state)
    return out


def ping(ip: str, timeout_ms: int = 700) -> bool:
    r = run(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=timeout_ms / 1000 + 4)
    return r.returncode == 0


def tcp_probe(ip: str, ports=(445, 139, 135, 80, 443, 22, 8080)) -> bool:
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                return True
        except OSError:
            continue
    return False


def probe_host(ip: str) -> bool:
    return ping(ip) or tcp_probe(ip)


def rev_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def nb_name(ip: str) -> str:
    try:
        r = run(["nbtstat", "-A", ip], timeout=6)
    except Exception:
        return ""
    m = re.search(r"^Name:\s*<([0-9A-Fa-f]{2})>\s+(\S+)", r.stdout or "", re.M | re.I)
    if not m:
        return ""
    name = m.group(2).rstrip(".").lower()
    return "" if name in ("", "<00>") else name


def cmd_env(_args) -> None:
    net = local_network()
    print(f"интерфейс   : {net['iface']}  ({net['mac']})")
    print(f"адрес       : {net['ip']}/{net['prefix']}")
    print(f"шлюз        : {net['gw']}")
    print(f"DNS         : {', '.join(net['dns']) or '-'}")
    print(f"OUI-база    : {OUI.path} {'загружена' if OUI.path.exists() else 'НЕТ (скачай ieee oui.txt)'}")
    print(f"база        : {DB_PATH}")
    print(f"права       : {'admin' if is_admin() else 'обычные (нужен admin для pktmon/SendARP)'}")
    print(f"pktmon      : {pktmon().returncode == 0}")
    r = run(["powershell", "-NoProfile", "-Command", "(Get-Command tshark -ErrorAction SilentlyContinue).Source"])
    print(f"wireshark   : {r.stdout.strip() or 'не установлен'}")


def cmd_discover(args) -> None:
    require_admin("Сканирование сети")
    net = local_network()
    me = net["ip"]
    gateway = net["gw"]
    if not OUI.load():
        print("[!] OUI-база не загружена, вендоры не будут определены")
    ips = subnet_ips(me, net["prefix"])
    if args.quick:
        ips = [ip for ip in ips if ip.rsplit(".", 1)[1] in ("1",) or ip == me]

    found: dict[str, str] = {}
    states: dict[str, str] = {}
    print(f"[*] Сканирую {net['ip']}/{net['prefix']} ({len(ips)} адресов): ICMP + TCP...")
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=96) as pool:
        futures = {pool.submit(probe_host, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass
    print(f"[*] Ответили: {len(alive)}. Читаю таблицу соседей...")

    base = me.rsplit(".", 1)[0]
    for ip, (mac, state) in neighbor_map().items():
        if not ip.startswith(base + ".") or ip.endswith(".255"):
            continue
        found[ip] = mac
        states[ip] = state
    for ip in alive:
        if ip not in found:
            found[ip] = ""
            states[ip] = "ping/tcp"
    if net.get("mac"):
        found[me] = net["mac"].lower()
        states[me] = "self"
    if gateway in found:
        states[gateway] = "роутер"
    if not found:
        sys.exit("[!] Устройств не найдено. Проверь адаптер и права администратора.")

    print(f"[*] Устройств в таблице: {len(found)}. Уточняю имена...")
    details: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        jb = {pool.submit(nb_name, ip): ip for ip in found}
        hb = {pool.submit(rev_dns, ip): ip for ip in found}
        res: dict[str, dict] = {ip: {"nbname": "", "hostname": ""} for ip in found}
        for fut in as_completed(jb):
            try:
                res[jb[fut]]["nbname"] = fut.result()
            except Exception:
                pass
        for fut in as_completed(hb):
            try:
                res[hb[fut]]["hostname"] = fut.result()
            except Exception:
                pass
    details.update(res)

    con = connect()
    ts = now()
    cur = con.cursor()
    new_devices: list[str] = []
    for ip, mac in sorted(found.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))):
        row = cur.execute("SELECT first_seen, mac, nbname, hostname FROM devices WHERE ip=?", (ip,)).fetchone()
        mac = mac or (row["mac"] if row else "")
        is_up = ip in set(alive) or ip == me
        vendor = OUI.lookup(mac) or mac_kind(mac)
        nb = details.get(ip, {}).get("nbname", "")
        hn = details.get(ip, {}).get("hostname", "")
        state = states.get(ip, "")
        if row is None:
            new_devices.append(ip)
            cur.execute(
                "INSERT INTO devices(ip,mac,vendor,hostname,nbname,first_seen,last_seen,"
                "is_gateway,source,state,online,last_alive) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (ip, mac, vendor, hn, nb, ts, ts, 1 if ip == gateway else 0, "sweep",
                 state, 1 if is_up else 0, ts if is_up else None),
            )
        else:
            changed = bool(row["mac"]) and row["mac"] != mac
            cur.execute(
                "UPDATE devices SET mac=?, vendor=?, hostname=COALESCE(NULLIF(?,''),hostname),"
                " nbname=COALESCE(NULLIF(?,''),nbname), last_seen=?, is_gateway=?, state=?,"
                " online=?, last_alive=COALESCE(?,last_alive) WHERE ip=?",
                (mac, vendor, hn, nb, ts, 1 if ip == gateway else 0, state,
                 1 if is_up else 0, ts if is_up else None, ip),
            )
            if changed:
                print(f"[!] Изменилось устройство {ip}: MAC {row['mac']} -> {mac}")
            elif row["nbname"] != nb and nb:
                print(f"[*] {ip}: имя {row['nbname'] or '-'} -> {nb}")
    con.commit()

    print()
    print(f"{'IP':<16}{'MAC':<20}{'Вендор / тип MAC':<38}{'Имя':<18}{'Статус':<14}Первый раз")
    print("-" * 128)
    for row in cur.execute("SELECT * FROM devices ORDER BY is_gateway DESC, online DESC, ip"):
        name = row["nbname"] or row["hostname"] or "-"
        if row["is_gateway"]:
            status = "РОУТЕР"
        elif row["online"]:
            status = "ОТВЕЧАЕТ"
        elif row["mac"]:
            status = "В СЕТИ (ARP)"
        else:
            status = "БЕЗ MAC"
        print(f"{row['ip']:<16}{row['mac'] or '-':<20}{(row['vendor'] or '-')[:37]:<38}"
              f"{name[:17]:<18}{status:<14}{row['first_seen']}")
    con.close()
    print()
    if new_devices:
        print(f"[+] Новых устройств: {len(new_devices)} -> {', '.join(new_devices)}")
    else:
        print("[+] Новых устройств нет")


# ------------------------------------------------------------------------ dns

def cmd_dns(args) -> None:
    action = args.action
    if action == "start":
        require_admin("Логирование DNS")
        ensure_dirs()
        if DNS_TAIL_PSID_alive():
            print(f"[*] Уже запущено (PID {read_pid()})")
            return
        r = run(["wevtutil", "sl", DNS_CHANNEL, "/e:true", "/q:true"], timeout=20)
        if r.returncode != 0:
            sys.exit(f"[!] wevtutil: {r.stderr or r.stdout}")
        run(["wevtutil", "cl", DNS_CHANNEL], timeout=30)
        script = (
            f"$p = Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',"
            f"'-File','{DNS_TAIL_PS1}','-OutCsv','{DNS_CSV}' -WindowStyle Hidden -PassThru; "
            f"$p.Id | Out-File -Encoding ascii '{DNS_PID}'"
        )
        r = run(["powershell", "-NoProfile", "-Command", script], timeout=30)
        if r.returncode != 0:
            sys.exit(f"[!] не удалось запустить tailer: {r.stderr or r.stdout}")
        time.sleep(3)
        print(f"[+] DNS-логирование запущено -> {DNS_CSV}")
        print(f"    Канал ETW: {DNS_CHANNEL}")
    elif action == "stop":
        pid = read_pid()
        if pid:
            run(["taskkill", "/PID", str(pid), "/T", "/F"], timeout=20)
            print(f"[*] Процесс {pid} остановлен")
        else:
            print("[*] Активного tailer не найдено")
        run(["wevtutil", "sl", DNS_CHANNEL, "/e:false"], timeout=20)
        print(f"[*] ETW-канал отключён. Лог: {DNS_CSV}")
    elif action == "status":
        run(["wevtutil", "cl", DNS_CHANNEL], timeout=30)
        alive = DNS_TAIL_PSID_alive()
        n = csv_lines(DNS_CSV)
        print(f"tailer      : {'работает (PID %s)' % read_pid() if alive else 'не запущен'}")
        print(f"канал ETW   : {'включён' if etw_enabled() else 'выключен'}")
        print(f"csv         : {DNS_CSV} ({n} строк)")
    elif action == "top":
        con = connect()
        n = import_dns_csv(con)
        if n:
            print(f"[*] Импортировано новых DNS-записей: {n}")
        rows = con.execute(
            "SELECT domain, COUNT(*) c FROM dns WHERE domain<>'' AND event=3006 GROUP BY domain ORDER BY c DESC LIMIT ?",
            (args.n,),
        ).fetchall()
        print(f"{'Домен':<52}Запросов")
        print("-" * 66)
        for r in rows:
            print(f"{r['domain'][:51]:<52}{r['c']}")
        con.close()
        if not rows:
            print("(пусто — запусти `netmon dns start`)")


def etw_enabled() -> bool:
    r = run(["wevtutil", "gl", DNS_CHANNEL], timeout=20)
    return bool(re.search(r"enabled:\s*true", r.stdout or "", re.I))


def read_pid() -> int:
    try:
        return int(DNS_PID.read_text().strip())
    except Exception:
        return 0


def DNS_TAIL_PSID_alive() -> bool:
    pid = read_pid()
    if not pid:
        return False
    r = run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], timeout=20)
    return str(pid) in (r.stdout or "")


def csv_lines(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with path.open("rb") as fh:
            return max(0, sum(1 for _ in fh) - 1)
    except Exception:
        return 0


def import_dns_csv(con) -> int:
    if not DNS_CSV.exists():
        return 0
    size = DNS_CSV.stat().st_size
    row = con.execute("SELECT bytes FROM imports WHERE name='dns_csv'").fetchone()
    offset = int(row["bytes"]) if row else 0
    if size < offset:
        offset = 0
    if size == offset:
        return 0
    added = 0
    consumed = offset
    with DNS_CSV.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        if offset:
            fh.seek(offset)
            consumed += len(fh.readline().encode("utf-8", "replace"))
        else:
            fh.readline()
        while True:
            pos = fh.tell()
            line = fh.readline()
            if not line:
                break
            consumed = pos + len(line.encode("utf-8", "replace"))
            try:
                parts = next(csv.reader([line]))
            except Exception:
                continue
            if len(parts) < 5 or not parts[0].strip():
                continue
            con.execute(
                "INSERT INTO dns(ts,event,domain,qtype,server,rcode) VALUES(?,?,?,?,?,?)",
                (parts[0].strip(), int(parts[1]) if parts[1].strip().isdigit() else 0,
                 parts[2].strip(), parts[3].strip(), parts[4].strip(),
                 parts[5].strip() if len(parts) > 5 else ""),
            )
            added += 1
    con.execute("INSERT OR REPLACE INTO imports(name,bytes,rows) VALUES('dns_csv',?,?)",
                (consumed, added))
    con.commit()
    return added


# -------------------------------------------------------------------- traffic

DETAIL_RE = re.compile(
    r"^\s*(?P<smac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s*>\s*"
    r"(?P<dmac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}),\s*"
    r"ethertype\s+(?P<etype>[A-Za-z0-9]+)\s+\(0x(?P<ehex>[0-9A-Fa-f]+)\)"
    r"(?:,\s*length\s+(?P<flen>\d+))?:\s*(?P<rest>.*)$"
)
IP4_RE = re.compile(r"^(?P<sip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<sport>\d+)\s*>\s*(?P<dip>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dport>\d+)")
TS_RE = re.compile(r"::(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)")
DIR_RE = re.compile(r"\b(Tx|Rx)\b")


def pktmon_capture(etl: Path, seconds: int, pkt_size: int, comp: str, log_mode: str = "circular") -> Path:
    pktmon("filter", "remove")
    pktmon("start", "--capture", "--comp", comp, "--pkt-size", str(pkt_size),
           "--log-mode", log_mode, "--file-name", str(etl), timeout=60)
    time.sleep(seconds)
    pktmon("stop", timeout=120)
    time.sleep(2)
    pktmon("filter", "remove")
    return etl


def parse_pktmon_txt(txt: Path) -> list[dict]:
    raw = txt.read_bytes()
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("latin-1", "replace")

    out: list[dict] = []
    cur_ts, cur_dir = "", ""
    for line in text.splitlines():
        if line.startswith("[") and "PktMon" in line:
            m = TS_RE.search(line)
            cur_ts = m.group("ts") if m else ""
            d = DIR_RE.search(line)
            cur_dir = d.group(1) if d else ""
            continue
        m = DETAIL_RE.match(line)
        if not m:
            continue
        rest = m.group("rest")
        rec = {
            "ts": cur_ts,
            "hdr_dir": cur_dir,
            "smac": m.group("smac").replace("-", ":").lower(),
            "dmac": m.group("dmac").replace("-", ":").lower(),
            "etype": m.group("etype").lower(),
            "flen": int(m.group("flen")) if m.group("flen") else 0,
        }
        ip = IP4_RE.match(rest)
        if ip:
            rec.update(sip=ip.group("sip"), sport=int(ip.group("sport")),
                       dip=ip.group("dip"), dport=int(ip.group("dport")),
                       proto="tcp" if "flags" in rest.lower() else "udp")
            pm = re.search(r"\b(TCP|UDP|ICMP)\b", rest)
            if pm:
                rec["proto"] = pm.group(1).lower()
            rec["ipv4"] = True
        out.append(rec)
    return out


def cmd_traffic(args) -> None:
    require_admin("Учёт трафика (pktmon)")
    net = local_network()
    ensure_dirs()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    etl = LOGS / f"traffic_{stamp}.etl"
    pkt_size = 0 if args.full else 128
    print(f"[*] Захват {args.seconds} с (pkt-size={pkt_size}, {'полный' if args.full else 'заголовки'})...")
    pktmon_capture(etl, args.seconds, pkt_size, args.comp)
    if not etl.exists() or etl.stat().st_size == 0:
        sys.exit("[!] ETL-файл не создан — проверь pktmon start вручную.")
    print(f"[*] ETL: {etl} ({human(etl.stat().st_size)})")

    txt = LOGS / f"traffic_{stamp}.txt"
    pktmon("etl2txt", str(etl), "--out", str(txt), timeout=600)
    if not txt.exists():
        sys.exit("[!] etl2txt не дал результат.")

    recs = parse_pktmon_txt(txt)
    print(f"[*] Разобрано пакетов: {len(recs)}")
    ip4 = [r for r in recs if r.get("ipv4")]
    print(f"[*] IPv4-пакетов: {len(ip4)}")
    if not ip4:
        print("[!] IPv4-пакетов не найдено. Возможно, pkt-size обрезает заголовок — попробуй --full.")
        etl.unlink(missing_ok=True)
        txt.unlink(missing_ok=True)
        return

    my = {m.replace("-", ":") for m in own_macs()}
    if net["mac"]:
        my.add(net["mac"].lower())
    subnet_base = net["ip"].rsplit(".", 1)[0]
    run_ts = now()

    acc: dict[tuple, list[int]] = {}
    no_len = 0
    for r in ip4:
        sip, dip = r["sip"], r["dip"]
        if sip == net["ip"] or r["smac"] in my:
            out_ip, out_peer, key_ip = net["ip"], dip, 0
        elif dip == net["ip"] or r["dmac"] in my:
            out_ip, out_peer, key_ip = net["ip"], sip, 1
        elif sip.startswith(subnet_base + "."):
            out_ip, out_peer, key_ip = sip, dip, 0
        elif dip.startswith(subnet_base + "."):
            out_ip, out_peer, key_ip = dip, sip, 1
        else:
            continue
        flen = r["flen"]
        if not flen:
            no_len += 1
            continue
        k = (out_ip, out_peer, r.get("proto", "?"), r["dport"] if key_ip == 0 else r["sport"])
        slot = acc.setdefault(k, [0, 0, 0, 0])
        if key_ip == 0:
            slot[0] += flen
            slot[2] += 1
        else:
            slot[1] += flen
            slot[3] += 1

    con = connect()
    con.executemany(
        "INSERT INTO pairs(run_ts,ip,peer,proto,port,rx_bytes,tx_bytes,rx_pkts,tx_pkts)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        [(run_ts, k[0], k[1], k[2], k[3], v[1], v[0], v[3], v[2]) for k, v in acc.items()],
    )
    con.commit()
    if no_len:
        print(f"[!] Пропущено пакетов без длины кадра: {no_len}")
    if not args.full:
        print("[!] pkt-size=128: байты посчитаны по заголовку. Для точного учёта запусти с --full.")
    if args.keep_txt:
        print(f"[*] Текстовый дамп сохранён: {txt}")
    else:
        txt.unlink(missing_ok=True)
        etl.unlink(missing_ok=True)
        print(f"[*] ETL/дамп удалены (оставь --keep-txt для офлайн-разбора)")

    print()
    print("=== Топ по исходящим (upload) ===")
    rows = con.execute(
        "SELECT peer,proto,port,tx_bytes,tx_pkts FROM pairs WHERE run_ts=? ORDER BY tx_bytes DESC LIMIT 12",
        (run_ts,),
    ).fetchall()
    for r in rows:
        print(f"  {r['peer']:<42}{r['proto']:<6}:{r['port']:<6}{human(r['tx_bytes']):>10}  пакетов {r['tx_pkts']}")
    print("=== Топ по входящим (download) ===")
    rows = con.execute(
        "SELECT peer,proto,port,rx_bytes,rx_pkts FROM pairs WHERE run_ts=? ORDER BY rx_bytes DESC LIMIT 12",
        (run_ts,),
    ).fetchall()
    for r in rows:
        print(f"  {r['peer']:<42}{r['proto']:<6}:{r['port']:<6}{human(r['rx_bytes']):>10}  пакетов {r['rx_pkts']}")
    print()
    print("=== Суммарно по устройствам ===")
    for r in con.execute(
        "SELECT ip, SUM(tx_bytes) t, SUM(rx_bytes) d FROM pairs WHERE run_ts=? GROUP BY ip ORDER BY (t+d) DESC",
        (run_ts,),
    ):
        print(f"  {r['ip']:<18}отдано {human(r['t']):>10}   принято {human(r['d']):>10}")
    con.close()
    print(f"\n[+] Снимок записан в {DB_PATH} (run_ts={run_ts})")


# ----------------------------------------------------------------------- pcap

def cmd_pcap(args) -> None:
    require_admin("Захват пакетов (pktmon)")
    ensure_dirs()
    if args.action == "start":
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        etl = CAPS / f"cap_{stamp}.etl"
        (CAPS / "current.etl").write_text(str(etl), encoding="utf-8")
        pktmon("filter", "remove")
        if args.port:
            pktmon("filter", "add", "port", "-d", "IPv4", "-p", str(args.port), timeout=30)
            print(f"[*] Фильтр: порт {args.port}")
        pktmon("start", "--capture", "--comp", "nics", "--pkt-size", str(args.pkt_size),
               "--log-mode", "circular", "--file-size", str(args.max_mb * 1024 * 1024),
               "--file-name", str(etl), timeout=60)
        print(f"[+] Захват идёт -> {etl} (макс {args.max_mb} МБ, только заголовки {args.pkt_size} Б)")
        print("    Остановить: netmon pcap stop")
    else:
        marker = CAPS / "current.etl"
        if not marker.exists():
            sys.exit("[!] Захват не запускался")
        etl = Path(marker.read_text().strip())
        pktmon("stop", timeout=180)
        time.sleep(3)
        pktmon("filter", "remove")
        pcap = CAPS / (etl.stem.replace("cap_", "") + ".pcapng")
        r = pktmon("etl2pcap", str(etl), "--out", str(pcap), timeout=600)
        if not pcap.exists():
            sys.exit(f"[!] etl2pcap не сработал: {r.stdout} {r.stderr}")
        print(f"[+] pcapng: {pcap} ({human(pcap.stat().st_size)})")
        print(f"    ETL оставлен: {etl}")
        marker.unlink(missing_ok=True)


# --------------------------------------------------------------------- router

class Telnet:
    IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

    def __init__(self, host: str, port: int = 23, timeout: float = 8.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def _clean(self, data: bytes) -> bytes:
        out, i = bytearray(), 0
        while i < len(data):
            b = data[i]
            if b == self.IAC and i + 1 < len(data):
                n = data[i + 1]
                if n == self.IAC:
                    out.append(self.IAC); i += 2; continue
                if n in (self.DO, self.DONT, self.WILL, self.WONT):
                    if n == self.DO:
                        self.sock.sendall(bytes([self.IAC, self.WONT, data[i + 2]]))
                    elif n == self.WILL:
                        self.sock.sendall(bytes([self.IAC, self.DONT, data[i + 2]]))
                    i += 3; continue
                if n == self.SB:
                    j = data.find(bytes([self.IAC, self.SE]), i)
                    i = (j + 2) if j != -1 else len(data); continue
                i += 2; continue
            out.append(b); i += 1
        return bytes(out)

    def read_until(self, patterns: list[bytes], deadline: float) -> bytes:
        rx = re.compile(b"|".join(re.escape(p) for p in patterns), re.I)
        end = time.time() + deadline
        while time.time() < end:
            m = rx.search(self.buf)
            if m:
                out, self.buf = self.buf[: m.end()], self.buf[m.end():]
                return out
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            self.buf += self._clean(chunk)
        out, self.buf = self.buf, b""
        return out

    def expect(self, pattern: bytes, deadline: float = 8.0) -> bytes:
        return self.read_until([pattern], deadline)

    def send(self, data: str) -> None:
        self.sock.sendall(data.encode("ascii", "replace"))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def router_password() -> str:
    pw = os.environ.get("NETMON_ROUTER_PASS")
    if pw:
        return pw
    import getpass
    return getpass.getpass("Пароль админа роутера (не сохраняется): ")


def router_connect(host: str, password: str, port: int = 23):
    t = Telnet(host, port)
    t.expect(b"ogin", 10)
    t.send(password + "\n")
    banner = t.expect(b":", 10)
    text = banner.decode("utf-8", "replace").lower()
    if "incorrect" in text or "wrong" in text or "error" in text:
        t.close()
        raise RuntimeError("Роутер отклонил пароль (Login incorrect).")
    probe = t.expect(b"#", 6) + t.expect(b"$", 2)
    if not probe.strip():
        t.send("\n")
        probe = t.expect(b"#", 6)
    return t


def router_exec(t: Telnet, cmd: str, deadline: float = 12.0) -> str:
    t.send(cmd + "\n")
    time.sleep(0.4)
    out = t.read_until([b"# ", b"$ ", b"> "], deadline)
    lines = out.decode("utf-8", "replace").splitlines()
    cleaned = []
    for ln in lines[1:]:
        if cmd.strip() in ln and len(ln) <= len(cmd) + 3:
            continue
        cleaned.append(ln.rstrip())
    return "\n".join(cleaned).strip()


def cmd_router(args) -> None:
    net = local_network()
    host = args.host or net["gw"]
    pw = router_password()
    try:
        t = router_connect(host, pw, args.port)
    except Exception as e:
        sys.exit(f"[!] Не удалось подключиться к {host}:{args.port}: {e}")
    print(f"[+] telnet {host}:{args.port} — подключено\n")
    for cmd in args.command:
        print(f"$ {cmd}")
        try:
            print(router_exec(t, cmd))
        except Exception as e:
            print(f"[!] ошибка: {e}")
        print()
    t.close()


def parse_arp_table(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            flags = parts[2]
            mac = parts[3]
            if re.match(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac) and int(flags, 16) & 0x2:
                out.append({"ip": parts[0], "mac": mac.lower(), "dev": parts[-1]})
    return out


CONNTRACK_RE = re.compile(
    r"src=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+dst=(?P<dst>\d{1,3}(?:\.\d{1,3}){3})"
    r"\s+sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)"
)


def parse_conntrack(text: str, subnet_base: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        if "UNREPLIED" in line and "ESTABLISHED" not in line:
            state = "UNREPLIED"
        elif "TIME_WAIT" in line:
            state = "TIME_WAIT"
        elif "ESTABLISHED" in line:
            state = "ESTABLISHED"
        else:
            state = line.split()[5] if len(line.split()) > 5 else "?"
        m = CONNTRACK_RE.search(line)
        if not m:
            continue
        src, dst = m.group("src"), m.group("dst")
        if src.startswith(subnet_base + ".") and not dst.startswith(subnet_base + "."):
            lip, rip, lp, rp, sdir = src, dst, m.group("sport"), m.group("dport"), "out"
        elif dst.startswith(subnet_base + ".") and not src.startswith(subnet_base + "."):
            lip, rip, lp, rp, sdir = dst, src, m.group("dport"), m.group("sport"), "in"
        else:
            lip, rip, lp, rp, sdir = src, dst, m.group("sport"), m.group("dport"), "lan"
        proto = "tcp" if " tcp " in line else ("udp" if " udp " in line else "?")
        out.append(dict(local_ip=lip, local_port=int(lp), remote_ip=rip,
                        remote_port=int(rp), proto=proto, state=state, src=sdir))
    return out


def parse_dev(text: str) -> list[dict]:
    out = []
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        vals = rest.split()
        if len(vals) < 16:
            continue
        try:
            out.append(dict(iface=name.strip(), rx_bytes=int(vals[0]), rx_pkts=int(vals[1]),
                            tx_bytes=int(vals[8]), tx_pkts=int(vals[9])))
        except ValueError:
            continue
    return out


def cmd_watch(args) -> None:
    net = local_network()
    host = args.host or net["gw"]
    pw = router_password()
    try:
        t = router_connect(host, pw, args.port)
    except Exception as e:
        sys.exit(f"[!] telnet {host}:{args.port}: {e}")
    OUI.load()
    con = connect()
    cur = con.cursor()
    subnet_base = net["ip"].rsplit(".", 1)[0]
    run_ts = now()
    print(f"[*] Опрос {host} каждые {args.interval} с, {args.rounds} раундов (Ctrl+C — стоп)")

    for rnd in range(1, args.rounds + 1):
        try:
            arp_txt = router_exec(t, "cat /proc/net/arp")
            ct_txt = router_exec(t, "cat /proc/net/nf_conntrack") or router_exec(t, "cat /proc/net/ip_conntrack")
            dev_txt = router_exec(t, "cat /proc/net/dev")
        except Exception as e:
            print(f"[!] раунд {rnd}: {e}")
            break

        arps = parse_arp_table(arp_txt)
        if not arps and rnd == 1:
            print("[!] ARP-таблица роутера пуста — возможно, нужен другой формат команды. Проверь `netmon router arp -an`")
        for a in arps:
            row = cur.execute("SELECT first_seen, mac FROM devices WHERE ip=?", (a["ip"],)).fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO devices(ip,mac,vendor,hostname,nbname,first_seen,last_seen,is_gateway,source)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (a["ip"], a["mac"], OUI.lookup(a["mac"]), "", "", run_ts, run_ts,
                     1 if a["ip"] == host else 0, "router_arp"))
            elif row["mac"] != a["mac"]:
                print(f"[!] {a['ip']}: MAC сменился {row['mac']} -> {a['mac']}")
                cur.execute("UPDATE devices SET mac=?, vendor=?, last_seen=? WHERE ip=?",
                            (a["mac"], OUI.lookup(a["mac"]), run_ts, a["ip"]))
            else:
                cur.execute("UPDATE devices SET last_seen=? WHERE ip=?", (run_ts, a["ip"]))

        flows = parse_conntrack(ct_txt, subnet_base)
        cur.executemany(
            "INSERT INTO flows(run_ts,local_ip,local_port,remote_ip,remote_port,proto,state,src)"
            " VALUES(?,?,?,?,?,?,?,?)",
            [(run_ts, f["local_ip"], f["local_port"], f["remote_ip"], f["remote_port"],
              f["proto"], f["state"], f["src"]) for f in flows],
        )
        devs = cur.execute("SELECT iface,rx_bytes,tx_bytes FROM iface WHERE run_ts=?", (run_ts,)).fetchone()
        if devs is None:
            cur.executemany(
                "INSERT INTO iface(run_ts,iface,rx_bytes,tx_bytes) VALUES(?,?,?,?)",
                [(run_ts, d["iface"], d["rx_bytes"], d["tx_bytes"]) for d in parse_dev(dev_txt)],
            )
        con.commit()

        print(f"  раунд {rnd}: устройств в ARP {len(arps)}, соединений {len(flows)}")
        if rnd < args.rounds:
            time.sleep(args.interval)
    t.close()
    print(f"\n[+] Данные в {DB_PATH} (run_ts={run_ts})")


# --------------------------------------------------------------------- report

def cmd_report(args) -> None:
    con = connect()
    cur = con.cursor()
    hours = args.hours
    n = import_dns_csv(con)
    if n:
        print(f"[*] Импортировано DNS-записей из CSV: {n}\n")

    print("=" * 78)
    print(f"ОТЧЁТ ПО СЕТИ  (окно {hours} ч)")
    print("=" * 78)

    print("\n[1] УСТРОЙСТВА НА РОУТЕРЕ (по ARP/conntrack)")
    rows = cur.execute(
        "SELECT ip,mac,vendor,nbname,hostname,first_seen,last_seen,is_gateway FROM devices"
        " ORDER BY is_gateway DESC, first_seen"
    ).fetchall()
    print(f"  {'IP':<16}{'MAC':<20}{'Вендор':<26}{'Имя':<18}Видно")
    print("  " + "-" * 74)
    for r in rows:
        nm = r["nbname"] or r["hostname"] or "-"
        print(f"  {r['ip']:<16}{r['mac'] or '-':<20}{(r['vendor'] or '-')[:25]:<26}{nm[:17]:<18}{r['last_seen'][:19]}")
    if not rows:
        print("  (нет данных — запусти `netmon discover` или `netmon watch`)")

    print("\n[2] ТОП УСТРОЙСТВ ПО ТРАФИКУ (pktmon, только видимый трафик хоста)")
    rows = cur.execute(
        "SELECT ip, SUM(tx_bytes) t, SUM(rx_bytes) d, COUNT(DISTINCT run_ts) runs FROM pairs"
        " WHERE run_ts >= datetime('now', ?) GROUP BY ip ORDER BY (t+d) DESC LIMIT 10",
        (f"-{hours} hours",),
    ).fetchall()
    if rows:
        for r in rows:
            print(f"  {r['ip']:<18}отдано {human(r['t'] or 0):>10}   принято {human(r['d'] or 0):>10}   замеров {r['runs']}")
    else:
        print("  (нет данных — запусти `netmon traffic --seconds 60 --full`)")

    print("\n[3] ТОП СОЕДИНЕНИЙ ПО УСТРОЙСТВАМ (conntrack роутера)")
    rows = cur.execute(
        "SELECT local_ip, COUNT(*) c, COUNT(DISTINCT remote_ip) peers FROM flows"
        " WHERE run_ts >= datetime('now', ?) GROUP BY local_ip ORDER BY c DESC LIMIT 10",
        (f"-{hours} hours",),
    ).fetchall()
    if rows:
        for r in rows:
            print(f"  {r['local_ip']:<18}соединений {r['c']:<8}уникальных пиров {r['peers']}")
    else:
        print("  (нет данных — запусти `netmon watch`)")

    print("\n[4] ТОП ДОМЕНОВ (DNS этого хоста, ETW)")
    rows = cur.execute(
        "SELECT domain, COUNT(*) c FROM dns WHERE ts >= datetime('now', ?) AND domain<>''"
        " GROUP BY domain ORDER BY c DESC LIMIT 15",
        (f"-{hours} hours",),
    ).fetchall()
    if rows:
        for r in rows:
            print(f"  {r['domain'][:60]:<62}{r['c']}")
    else:
        print("  (нет данных — запусти `netmon dns start`, подожди, потом `netmon dns stop`)")

    print("\n[5] ИНТЕРФЕЙСЫ РОУТЕРА (счётчики /proc/net/dev)")
    rows = cur.execute(
        "SELECT iface, MAX(rx_bytes) rx, MAX(tx_bytes) tx FROM iface"
        " WHERE run_ts >= datetime('now', ?) GROUP BY iface ORDER BY (rx+tx) DESC LIMIT 10",
        (f"-{hours} hours",),
    ).fetchall()
    for r in rows:
        print(f"  {r['iface']:<20}rx {human(r['rx'] or 0):>12}   tx {human(r['tx'] or 0):>12}")
    if not rows:
        print("  (нет данных)")

    print("\n[6] НОВЫЕ УСТРОЙСТВА ЗА ОКНО")
    rows = cur.execute(
        "SELECT ip, mac, vendor, first_seen FROM devices WHERE first_seen >= datetime('now', ?)"
        " ORDER BY first_seen",
        (f"-{hours} hours",),
    ).fetchall()
    for r in rows:
        print(f"  {r['ip']:<16}{r['mac'] or '-':<20}{(r['vendor'] or '-')[:30]:<32}{r['first_seen']}")
    if not rows:
        print("  (нет)")
    print()
    con.close()


# ------------------------------------------------------------------------ cli

def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog="netmon", description="Мониторинг локальной сети")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("env", help="показать окружение").set_defaults(fn=cmd_env)

    d = sub.add_parser("discover", help="инвентаризация устройств")
    d.add_argument("--quick", action="store_true", help="только шлюз и я")
    d.set_defaults(fn=cmd_discover)

    dn = sub.add_parser("dns", help="логирование DNS (ETW)")
    dn.add_argument("action", choices=["start", "stop", "status", "top"])
    dn.add_argument("-n", type=int, default=25, help="сколько доменов в top")
    dn.set_defaults(fn=cmd_dns)

    t = sub.add_parser("traffic", help="учёт трафика по устройствам")
    t.add_argument("--seconds", type=int, default=60)
    t.add_argument("--full", action="store_true", help="полный пакет вместо заголовков (точнее, тяжелее)")
    t.add_argument("--comp", default="nics", choices=["nics", "all"])
    t.add_argument("--keep-txt", action="store_true")
    t.set_defaults(fn=cmd_traffic)

    p = sub.add_parser("pcap", help="захват пакетов")
    p.add_argument("action", choices=["start", "stop"])
    p.add_argument("--port", type=int, default=0, help="фильтр по порту (0 = без фильтра)")
    p.add_argument("--pkt-size", type=int, default=128)
    p.add_argument("--max-mb", type=int, default=512)
    p.set_defaults(fn=cmd_pcap)

    r = sub.add_parser("router", help="команда в telnet-шелле роутера")
    r.add_argument("command", nargs="+")
    r.add_argument("--host", default="")
    r.add_argument("--port", type=int, default=23)
    r.set_defaults(fn=cmd_router)

    w = sub.add_parser("watch", help="опрос роутера: ARP + conntrack + счётчики")
    w.add_argument("--seconds", type=int, default=0, help="за сколько секунд идти (0 = один раунд)")
    w.add_argument("--interval", type=int, default=30)
    w.add_argument("--rounds", type=int, default=1)
    w.add_argument("--host", default="")
    w.add_argument("--port", type=int, default=23)
    w.set_defaults(fn=cmd_watch)

    rp = sub.add_parser("report", help="сводка")
    rp.add_argument("--hours", type=int, default=24)
    rp.set_defaults(fn=cmd_report)

    args = ap.parse_args()
    if args.cmd == "watch" and args.seconds:
        args.rounds = max(1, round(args.seconds / max(1, args.interval)))
    args.fn(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Прервано")
    except subprocess.TimeoutExpired as e:
        sys.exit(f"[!] Таймаут команды: {e.cmd}")
