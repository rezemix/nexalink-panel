#!/usr/bin/env python3
"""
Агент ноды. Раз в POLL секунд:
  1. снимает трафик пользователей (xray stats, статистика сервисов);
  2. забирает с панели желаемое состояние и применяет его, если версия изменилась;
  3. отправляет отчёт (трафик, версия ядра, ошибки).

Только стандартная библиотека Python 3.8+.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

AGENT_VERSION = "1.3.0"

CONF_PATH  = "/etc/vpnagent/agent.json"
STATE_PATH = "/var/lib/vpnagent/state.json"
XRAY_BIN   = "/usr/local/bin/xray"
XRAY_CONF  = "/usr/local/etc/xray/config.json"
XRAY_API   = "127.0.0.1:10085"
UNIT_DIR   = "/etc/systemd/system"
CERT_DIR   = "/etc/vpnagent/certs"
ASSET_DIR  = "/usr/local/share/xray"   # рядом с geosite.dat — xray ищет ext-файлы здесь
ACME       = "/root/.acme.sh/acme.sh"
# если :80 занят (например, Caddy панели), acme.sh слушает здесь, а Caddy
# проксирует на него /.well-known/acme-challenge/
ACME_ALT_PORT = 8402
POLL       = 10


def log(*args):
    print(time.strftime("%H:%M:%S"), *args, flush=True)


# --- утилиты ---

def run(cmd, timeout=60, shell=False):
    # под systemd нет HOME — acme.sh и прочие установщики без него ставятся мимо /root
    env = {**os.environ, "HOME": os.environ.get("HOME") or "/root"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell, env=env)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def write_file(path, content, mode="644"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(tmp, int(str(mode), 8))
    os.replace(tmp, path)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def is_active(unit):
    return run(["systemctl", "is-active", unit])[1] == "active"


def unit_uptime(unit):
    """Секунды с запуска юнита или None."""
    rc, out = run(["systemctl", "show", unit, "-p", "ActiveEnterTimestampMonotonic", "--value"])
    try:
        started = int(out) / 1e6
        with open("/proc/uptime") as f:
            up = float(f.read().split()[0])
        return max(0, int(up - started)) if started else None
    except Exception:
        return None


class Panel:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token

    def request(self, method, path, body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
            "User-Agent": f"vpnagent/{AGENT_VERSION}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = r.read()
        return payload if raw else json.loads(payload)


# --- xray ---

def xray_version():
    rc, out = run([XRAY_BIN, "version"])
    parts = out.split()
    return parts[1] if rc == 0 and len(parts) > 1 else None


def _without_clients(cfg):
    c = copy.deepcopy(cfg)
    for ib in c.get("inbounds", []):
        ib.get("settings", {}).pop("clients", None)
    return json.dumps(c, sort_keys=True)


def _clients_by_tag(cfg):
    out = {}
    for ib in (cfg or {}).get("inbounds", []):
        clients = ib.get("settings", {}).get("clients")
        if clients is not None:
            out[ib["tag"]] = {c["email"]: c for c in clients}
    return out


def xray_hot_update(old, new):
    """Добавить/удалить пользователей через API без перезапуска. False — нужен рестарт."""
    old_c, new_c = _clients_by_tag(old), _clients_by_tag(new)
    inbounds = {ib["tag"]: ib for ib in new.get("inbounds", [])}
    for tag, wanted in new_c.items():
        have = old_c.get(tag, {})
        removed = [e for e in have if e not in wanted or have[e] != wanted[e]]
        added = [c for e, c in wanted.items() if e not in have or have[e] != c]
        for i in range(0, len(removed), 200):
            rc, out = run([XRAY_BIN, "api", "rmu", f"--server={XRAY_API}", f"-tag={tag}"] + removed[i:i + 200])
            if rc != 0:
                log("rmu failed:", out)
                return False
        if added:
            ib = copy.deepcopy(inbounds[tag])
            ib["settings"]["clients"] = added
            fd, tmp = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w") as f:
                json.dump({"inbounds": [ib]}, f)
            rc, out = run([XRAY_BIN, "api", "adu", f"--server={XRAY_API}", tmp])
            os.unlink(tmp)
            if rc != 0 or "failed" in out.lower():
                log("adu failed:", out)
                return False
        if removed or added:
            log(f"{tag}: +{len(added)} -{len(removed)} пользователей (без перезапуска)")
    return True


def apply_xray(new):
    if new is None:
        if is_active("xray"):
            run(["systemctl", "disable", "--now", "xray"])
            log("xray остановлен: на ноде нет xray-инбаундов")
        return
    old = load_json(XRAY_CONF, None)
    if old == new and is_active("xray"):
        return
    if old and is_active("xray") and _without_clients(old) == _without_clients(new):
        if xray_hot_update(old, new):
            write_file(XRAY_CONF, json.dumps(new, indent=2))
            return
    fd, tmp = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(new, f, indent=2)
    rc, out = run([XRAY_BIN, "run", "-test", "-c", tmp])
    if rc != 0:
        os.unlink(tmp)
        raise RuntimeError("xray config test failed: " + out[-500:])
    os.chmod(tmp, 0o644)
    os.makedirs(os.path.dirname(XRAY_CONF), exist_ok=True)
    os.replace(tmp, XRAY_CONF)
    run(["systemctl", "enable", "xray"])
    rc, out = run(["systemctl", "restart", "xray"])
    time.sleep(1)
    if not is_active("xray"):
        raise RuntimeError("xray не запустился: " + run(["journalctl", "-u", "xray", "-n", "5", "--no-pager"])[1][-500:])
    log("xray перезапущен с новым конфигом")


def xray_stats():
    if not is_active("xray"):
        return {}, 0
    traffic = {}
    rc, out = run([XRAY_BIN, "api", "statsquery", f"--server={XRAY_API}", "-pattern", "user>>>", "-reset"])
    if rc == 0 and out:
        try:
            for s in json.loads(out).get("stat", []):
                parts = s["name"].split(">>>")
                if len(parts) == 4 and parts[2] == "traffic":
                    t = traffic.setdefault(parts[1], [0, 0])
                    t[0 if parts[3] == "uplink" else 1] += int(s.get("value", 0) or 0)
        except Exception as e:
            log("statsquery parse:", e)
    online = 0
    rc, out = run([XRAY_BIN, "api", "statsgetallonlineusers", f"--server={XRAY_API}"])
    if rc == 0 and out:
        try:
            data = json.loads(out)
            users = data.get("users", data) if isinstance(data, dict) else data
            online = len(users or [])
        except Exception:
            pass
    return traffic, online


# --- сертификаты ---

def _port_busy(port):
    return bool(run(["ss", "-Hltn", f"sport = :{port}"])[1].strip())


def _issue_cert(domain, path):
    if not os.path.exists(ACME):
        run(["apt-get", "install", "-y", "-qq", "socat", "cron"], timeout=300)  # cron — автопродление acme.sh
        rc, out = run(["bash", "-c", f"curl -fsSL https://get.acme.sh | sh -s email=admin@{domain}"], timeout=300)
        if rc != 0 or not os.path.exists(ACME):
            raise RuntimeError("acme.sh install: " + out[-300:])
    port = ACME_ALT_PORT if _port_busy(80) else 80
    if port == 80 and "Status: active" in run(["ufw", "status"])[1]:
        run(["ufw", "allow", "80/tcp"])
    rc, out = run([ACME, "--issue", "-d", domain, "--standalone", "--httpport", str(port),
                   "--server", "letsencrypt"], timeout=300)
    if rc not in (0, 2):  # 2 — уже выпущен
        raise RuntimeError(f"сертификат {domain}: " + out[-400:])
    os.makedirs(path, exist_ok=True)
    rc, out = run([ACME, "--install-cert", "-d", domain, "--key-file", f"{path}/key.pem",
                   "--fullchain-file", f"{path}/fullchain.pem",
                   "--reloadcmd", f"chmod 644 {path}/key.pem; systemctl restart xray"], timeout=120)
    if rc != 0:
        raise RuntimeError(f"install-cert {domain}: " + out[-300:])
    log(f"сертификат {domain} выпущен")


def ensure_certs(certs, state):
    """Возвращает (домены с готовым сертификатом, ошибки). Неудачи повторяются раз в 10 минут."""
    ready, errors = set(), []
    fails = state.setdefault("cert_fail", {})
    for c in certs:
        d = c["domain"]
        path = os.path.join(CERT_DIR, d)
        if os.path.exists(f"{path}/fullchain.pem") and os.path.exists(f"{path}/key.pem"):
            ready.add(d)
            continue
        if time.time() - fails.get(d, 0) < 600:
            errors.append(f"сертификат {d}: ждём повтора")
            continue
        try:
            _issue_cert(d, path)
            ready.add(d)
            fails.pop(d, None)
        except Exception as e:
            fails[d] = time.time()
            errors.append(str(e))
    return ready, errors


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_assets(assets, panel):
    """Доп. файлы xray (расширенный список рекламы): скачиваем, если sha256 изменился.
    → имена файлов, которые лежат на месте и совпадают с панелью."""
    ready = set()
    for a in assets:
        path = os.path.join(ASSET_DIR, a["name"])
        try:
            if not (os.path.exists(path) and _sha256_file(path) == a["sha256"]):
                data = panel.request("GET", a["path"], raw=True)
                if hashlib.sha256(data).hexdigest() != a["sha256"]:
                    raise ValueError("контрольная сумма не совпала")
                os.makedirs(ASSET_DIR, exist_ok=True)
                with open(path + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(path + ".tmp", path)
                log(f"файл {a['name']} обновлён ({len(data)} байт)")
            ready.add(a["name"])
        except Exception as e:
            log(f"файл {a['name']} не скачан: {e}")
    return ready


def prepare_xray(cfg, ready, assets_ready=None, assets=()):
    """Убирает служебные пометки; инбаунды без сертификата временно выключаются,
    правила со ссылками на нескачанные ext-файлы — тоже (иначе xray не стартует)."""
    if cfg is None:
        return None, []
    cfg = copy.deepcopy(cfg)
    missing = [a["name"] for a in assets if a["name"] not in (assets_ready or set())]
    if missing:
        rules = []
        for r in cfg.get("routing", {}).get("rules", []):
            if "domain" in r:
                r["domain"] = [d for d in r["domain"] if not any(d.startswith(f"ext:{m}:") for m in missing)]
                if not r["domain"]:
                    continue
            rules.append(r)
        cfg.setdefault("routing", {})["rules"] = rules
    kept, dropped = [], []
    for ib in cfg.get("inbounds", []):
        need = ib.pop("_requires_cert", [])
        if all(d in ready for d in need):
            kept.append(ib)
        else:
            dropped.append(ib["tag"])
    cfg["inbounds"] = kept
    dropped_tags = set(dropped)
    cfg.get("routing", {})["rules"] = [r for r in cfg.get("routing", {}).get("rules", [])
                                       if not dropped_tags & set(r.get("inboundTag", []))]
    return (cfg if kept else None), dropped


# --- сервисы на своих ядрах ---

def apply_services(services, state):
    current = state.setdefault("services", {})
    wanted = {s["name"]: s for s in services}
    for name in list(current):
        if name not in wanted:
            unit = current[name]["unit"]
            run(["systemctl", "disable", "--now", unit])
            try:
                os.unlink(os.path.join(UNIT_DIR, unit))
            except FileNotFoundError:
                pass
            run(["systemctl", "daemon-reload"])
            del current[name]
            log(f"сервис {name} удалён")
    for name, s in wanted.items():
        h = hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()
        unit = s["unit"]["name"]
        if current.get(name, {}).get("hash") == h and is_active(unit):
            continue
        inst = s.get("install")
        if inst and run(inst["check"], shell=True)[0] != 0:
            log(f"{name}: установка ядра")
            rc, out = run(["bash", "-c", inst["script"]], timeout=600)
            if rc != 0:
                raise RuntimeError(f"{name}: установка не удалась: {out[-500:]}")
        for f in s.get("files", []):
            write_file(f["path"], f["content"], f.get("mode", "644"))
        write_file(os.path.join(UNIT_DIR, unit), s["unit"]["content"])
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", unit])
        run(["systemctl", "restart", unit])
        time.sleep(1)
        if not is_active(unit):
            raise RuntimeError(f"{unit} не запустился: " +
                               run(["journalctl", "-u", unit, "-n", "5", "--no-pager"])[1][-500:])
        current[name] = {"hash": h, "unit": unit, "stats": s.get("stats")}
        log(f"сервис {name} применён")


def service_stats(state):
    traffic = {}
    for name, meta in state.get("services", {}).items():
        st = meta.get("stats")
        if not st or st.get("type") != "hysteria2":
            continue
        try:
            req = urllib.request.Request(st["url"], headers={"Authorization": st["secret"]})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read() or b"{}")
            for user, v in data.items():
                t = traffic.setdefault(user, [0, 0])
                t[0] += int(v.get("rx", 0))
                t[1] += int(v.get("tx", 0))
        except Exception as e:
            log(f"{name}: stats:", e)
    return traffic


# --- фаервол ---

def apply_firewall(rules, state):
    if "Status: active" not in run(["ufw", "status"])[1]:
        return
    wanted = {f"{r['port']}/{r['proto']}" for r in rules}
    have = set(state.get("firewall", []))
    for r in wanted - have:
        run(["ufw", "allow", r])
    for r in have - wanted:
        run(["ufw", "delete", "allow", r])
    state["firewall"] = sorted(wanted)


# --- состояние сервера ---

_net_prev = {}


def system_stats():
    """Нагрузка ноды для панели: load, CPU, RAM, диск, аптайм, скорость сети."""
    st = {}
    try:
        with open("/proc/loadavg") as f:
            st["load"] = [float(x) for x in f.read().split()[:3]]
        st["cpus"] = os.cpu_count() or 1
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.split()[0]) * 1024
        st["mem_total"] = mem.get("MemTotal", 0)
        st["mem_used"] = mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)
        d = os.statvfs("/")
        st["disk_total"] = d.f_blocks * d.f_frsize
        st["disk_used"] = (d.f_blocks - d.f_bfree) * d.f_frsize
        with open("/proc/uptime") as f:
            st["uptime"] = int(float(f.read().split()[0]))
        rx = tx = 0
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, data = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                v = data.split()
                rx += int(v[0])
                tx += int(v[8])
        now = time.time()
        if _net_prev:
            dt = max(now - _net_prev["t"], 1)
            st["net_rx_bps"] = int((rx - _net_prev["rx"]) / dt)
            st["net_tx_bps"] = int((tx - _net_prev["tx"]) / dt)
        _net_prev.update(t=now, rx=rx, tx=tx)
    except Exception as e:
        log("system stats:", e)
    return st


# --- главный цикл ---

def self_update(panel):
    code = panel.request("GET", "/install/agent.py", raw=True)
    if b"AGENT_VERSION" not in code:
        return
    write_file(os.path.abspath(__file__), code.decode(), "755")
    log("агент обновлён, перезапуск")
    sys.exit(0)


def merge(into, traffic):
    for user, (up, down) in traffic.items():
        t = into.setdefault(user, [0, 0])
        t[0] += up
        t[1] += down


def main():
    conf = load_json(CONF_PATH, None)
    if not conf:
        sys.exit(f"нет {CONF_PATH}")
    panel = Panel(conf["panel"], conf["token"])
    state = load_json(STATE_PATH, {})
    state.setdefault("pending", {})
    log(f"агент {AGENT_VERSION}, панель {panel.url}")

    while True:
        error = None
        traffic, online = xray_stats()
        merge(state["pending"], traffic)
        merge(state["pending"], service_stats(state))

        try:
            cfg = panel.request("GET", f"/api/agent/config?version={state.get('version') or ''}")
            if cfg.get("agent_version") and cfg["agent_version"] != AGENT_VERSION:
                self_update(panel)
            if not cfg.get("unchanged"):
                log("новая версия конфига", cfg["version"])
                ready, cert_errors = ensure_certs(cfg.get("certificates", []), state)
                assets = cfg.get("assets", [])
                assets_ready = ensure_assets(assets, panel)
                xray_cfg, dropped = prepare_xray(cfg.get("xray"), ready, assets_ready, assets)
                apply_xray(xray_cfg)
                apply_services(cfg.get("services", []), state)
                apply_firewall(cfg.get("firewall", []), state)
                missing = {a["name"] for a in assets} - assets_ready
                if missing:
                    raise RuntimeError(f"файлы {', '.join(sorted(missing))} не скачаны — правила с ними временно выключены")
                if dropped:
                    # остальное применено; повторим, когда появится сертификат
                    raise RuntimeError(f"инбаунды {', '.join(dropped)} ждут сертификат: " + "; ".join(cert_errors))
                state["version"] = cfg["version"]
        except urllib.error.URLError as e:
            error = f"panel: {e}"
        except Exception as e:
            error = str(e)
            state["version"] = None  # повторим применение в следующем цикле

        if error:
            log("ошибка:", error)
        try:
            panel.request("POST", "/api/agent/report", {
                "agent_version": AGENT_VERSION,
                "core_version": xray_version(),
                "core_uptime": unit_uptime("xray") if is_active("xray") else None,
                "applied_version": state.get("version"),
                "error": error,
                "users_online": online,
                "traffic": state["pending"],
                "sys": system_stats(),
            })
            state["pending"] = {}
        except Exception as e:
            log("отчёт не отправлен:", e)

        write_file(STATE_PATH, json.dumps(state), "600")
        time.sleep(POLL)


if __name__ == "__main__":
    main()
