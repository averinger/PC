import socket, ssl, struct, re, base64, threading, time, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import C, SNMP_COMMUNITIES, ROUTER_PASSWORDS_BASE, PANELS
from .utils import progress_end, progress_line, check_external_tools
from .http_utils import http_get

ROUTER_DEFAULTS = [(u,p) for u in ['admin','root','user'] for p in
                   ['admin','password','1234','12345','123456','root','guest','']]

# ─── SNMP ───
def _snmp_get(ip, community, timeout=2):
    try:
        comm = community.encode()
        pkt = (b'\x30' + bytes([26+len(comm)]) +
               b'\x02\x01\x00' + b'\x04' + bytes([len(comm)]) + comm +
               b'\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00'
               b'\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        s.sendto(pkt, (ip, 161)); d, _ = s.recvfrom(4096); s.close()
        if d and len(d) > 20: return d
    except: pass
    return None

def check_snmp_brute(ip, communities=None, timeout=2):
    """Перебор community strings SNMP"""
    communities = communities or SNMP_COMMUNITIES
    found = []
    for c in communities:
        d = _snmp_get(ip, c, timeout)
        if d:
            txt = d.decode('latin-1','ignore')
            m = re.search(r'[\x20-\x7e]{5,}', txt)
            found.append((c, m.group(0).strip() if m else '?'))
    return found

def check_snmp_public(ip, timeout=2):
    """Совместимость со старым API"""
    r = check_snmp_brute(ip, ['public','private'], timeout)
    return r[0][1] if r else None

# ─── SMB / EternalBlue ───
def check_smb_shares(ip, timeout=3):
    try:
        pkt = bytes.fromhex(
            '00000085ff534d42720000000018012800000000000000000000000000000000'
            '000000000000000000002f4b0000c1554d53420000000000')
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, 445))
        s.sendall(pkt); d = s.recv(1024); s.close()
        if b'\xffSMB' in d: return 'SMB1 (устаревший!)'
        if b'\xfeSMB' in d: return 'SMB2/3'
        return 'SMB отвечает'
    except: return None

def check_eternalblue(ip, timeout=4):
    """MS17-010 (EternalBlue) — простая проверка Trans2"""
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, 445))
        # SMB1 Negotiate
        neg = bytes.fromhex(
            '00000085ff534d42720000000018012800000000000000000000000000000000'
            '000000000000000000002f4b0000c1554d53420000000000')
        s.sendall(neg); d = s.recv(1024)
        if b'\xffSMB' not in d: s.close(); return None
        s.close()
        # Второй этап — Trans2 на \PIPE\
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, 445))
        trans2 = bytes.fromhex(
            '0000004aff534d42720000000018012800000000000000000000000000000000'
            '0000000000000000000000000010000a4c0000000000000000000000000000'
            '00000000000000000000000000000000000000000000000000')
        s.sendall(trans2)
        try:
            d = s.recv(1024)
            s.close()
            # Если SMB1 отвечает на Trans2 — уязвим (грубое приближение)
            if b'\xffSMB' in d:
                return 'Возможно уязвим к MS17-010 (требуется confirm)'
        except: s.close()
    except: pass
    return None

# ─── Базы данных ───
def check_mongodb(ip, port=27017, timeout=3):
    try:
        msg = struct.pack('<iiii', 0, 0, 0, 2013) + b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        s.sendall(msg); d = s.recv(2048); s.close()
        if b'ismaster' in d.lower() or b'maxWireVersion' in d:
            if b'unauthorized' in d.lower(): return 'требует пароль'
            return 'ОТКРЫТ БЕЗ ПАРОЛЯ'
        return None
    except: return None

def check_elasticsearch(ip, port=9200, timeout=3):
    try:
        st, _, bd = http_get(ip, port, '/', timeout=timeout, max_bytes=5000)
        if st == 200 and 'cluster_name' in bd:
            m = re.search(r'"number"\s*:\s*"([^"]+)"', bd)
            return f'ОТКРЫТ (v{m.group(1) if m else "?"})'
        if st == 401: return 'требует пароль'
    except: pass
    return None

def check_memcached(ip, port=11211, timeout=3):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        s.sendall(b'stats\r\n'); d = s.recv(4096).decode('utf-8','ignore'); s.close()
        if 'STAT ' in d:
            m = re.search(r'STAT version\s+(\S+)', d)
            return f'ОТКРЫТ (v{m.group(1) if m else "?"})'
    except: pass
    return None

def check_postgres_default(ip, port=5432, timeout=3):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        s.sendall(struct.pack('!ii', 8, 80877103))
        r = s.recv(1); s.close()
        if r == b'S': return 'отвечает (SSL)'
        if r == b'N': return 'отвечает'
    except: pass
    return None

def check_redis(ip, port=6379, timeout=3):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        s.sendall(b'INFO\r\n'); d = s.recv(4096).decode('utf-8','ignore'); s.close()
        if 'redis_version' in d:
            m = re.search(r'redis_version:(\S+)', d)
            return f'ОТКРЫТ (v{m.group(1) if m else "?"})'
        if 'NOAUTH' in d: return 'требует пароль'
    except: pass
    return None

# ─── Веб / API ───
def check_k8s_api(ip, port=6443, timeout=4):
    try:
        st, _, bd = http_get(ip, port, '/version', https=True, timeout=timeout, max_bytes=3000)
        if st == 200 and 'gitVersion' in bd:
            m = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', bd)
            return f'ОТКРЫТ (k8s {m.group(1) if m else "?"})'
        if st in (401, 403): return 'требует пароль'
    except: pass
    return None

def check_http_basic(ip, port=80, https=False, timeout=4):
    paths = ['/', '/admin', '/setup', '/management']
    for path in paths:
        st, hd, _ = http_get(ip, port, path, https=https, timeout=timeout, max_bytes=2000)
        if st != 401: continue
        for user, pw in ROUTER_DEFAULTS[:15]:
            try:
                if https:
                    ctx = ssl._create_unverified_context()
                    s = socket.socket(); s.settimeout(timeout)
                    s = ctx.wrap_socket(s, server_hostname=ip)
                else:
                    s = socket.socket(); s.settimeout(timeout)
                s.connect((ip, port))
                cred = base64.b64encode(f'{user}:{pw}'.encode()).decode()
                req = (f'GET {path} HTTP/1.0\r\nHost: {ip}\r\n'
                       f'Authorization: Basic {cred}\r\nConnection: close\r\n\r\n')
                s.sendall(req.encode())
                r = s.recv(256).decode('utf-8','ignore'); s.close()
                if r.startswith('HTTP/') and ' 200 ' in r: return [(path, user, pw)]
            except: pass
    return []

def check_ftp_default(ip, port=21, timeout=4):
    found = []
    for user, pw in ROUTER_DEFAULTS:
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
            s.settimeout(2); s.recv(256)
            s.sendall(f'USER {user}\r\n'.encode())
            r1 = s.recv(256).decode('utf-8','ignore')
            if r1.startswith('230'): found.append((user, pw)); s.close(); break
            if r1.startswith('331'):
                s.sendall(f'PASS {pw}\r\n'.encode())
                r2 = s.recv(256).decode('utf-8','ignore')
                if r2.startswith('230'): found.append((user, pw)); s.close(); break
            s.close()
        except: pass
    return found

def check_telnet_default(ip, port=23, timeout=4):
    found = []
    for user, pw in ROUTER_DEFAULTS[:10]:
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
            time.sleep(0.5)
            try:
                s.settimeout(1.5); b = s.recv(512)
                t = b.decode('utf-8','ignore').lower()
                if 'login' in t or 'username' in t:
                    s.sendall((user+'\r\n').encode()); time.sleep(0.5)
                    s.sendall((pw+'\r\n').encode()); time.sleep(0.7)
                    try:
                        r = s.recv(512).decode('utf-8','ignore').lower()
                        if ('#' in r or '$' in r) and 'incorrect' not in r:
                            found.append((user, pw)); s.close(); break
                    except: pass
            except: pass
            s.close()
        except: pass
    return found

# ─── TLS / Headers / Панели ───
def check_tls_cert(ip, port=443, timeout=5):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.socket(); s.settimeout(timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip); ss.connect((ip, port))
        c = ss.getpeercert(); ci = ss.cipher(); ver = ss.version(); ss.close()
        if not c: return None
        sub = dict(x[0] for x in c.get('subject',[]))
        iss = dict(x[0] for x in c.get('issuer',[]))
        weak = []
        if ver in ('TLSv1','TLSv1.1','SSLv3'): weak.append(f'старый протокол {ver}')
        if ci and ci[0] in ('RC4-SHA','DES-CBC3-SHA','RC4-MD5'): weak.append(f'слабый шифр {ci[0]}')
        return {'version':ver,'cipher':ci[0] if ci else '?',
                'subject_cn':sub.get('commonName','?'),
                'issuer_cn':iss.get('commonName','?'),
                'not_after':c.get('notAfter','?'),
                'san':c.get('subjectAltName',[]), 'weak': weak}
    except: return None

def check_http_headers(ip, port=80, https=False, timeout=4):
    st, hd, _ = http_get(ip, port, '/', https=https, timeout=timeout, max_bytes=5000)
    if st is None: return None
    req = {'strict-transport-security':'HSTS','x-frame-options':'X-Frame-Options',
           'x-content-type-options':'X-Content-Type-Options',
           'content-security-policy':'CSP','referrer-policy':'Referrer-Policy'}
    missing = [v for k,v in req.items() if k not in hd]
    present = [v for k,v in req.items() if k in hd]
    return {'missing': missing, 'present': present}

def check_exposed_panels(ip, port=80, https=False, timeout=3):
    found = []
    for path, name in PANELS.items():
        st, _, bd = http_get(ip, port, path, https=https, timeout=timeout, max_bytes=2000)
        if st in (200, 301, 302):
            found.append((path, name, st))
    return found

def check_git_exposure(ip, port=80, https=False, timeout=4):
    found = []
    for p in ['/.git/HEAD', '/.git/config']:
        st,_,bd = http_get(ip, port, p, https=https, timeout=timeout, max_bytes=2000)
        if st == 200 and ('ref:' in bd or '[core]' in bd): found.append(p)
    return found

# ─── NFS / rsync / Прочее ───
def check_nfs_exports(ip, timeout=3):
    tools = check_external_tools()
    if not tools.get('showmount'): return []
    try:
        r = subprocess.run(['showmount','-e',ip], capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and 'Export list' in r.stdout:
            return [l.strip() for l in r.stdout.split('\n')[1:] if l.strip()]
    except: pass
    return []

def check_rsync_modules(ip, port=873, timeout=4):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        s.recv(512); s.sendall(b'\r\n'); time.sleep(1)
        d = s.recv(2048).decode('utf-8','ignore'); s.close()
        mods = []
        for l in d.split('\n'):
            p = l.split('\t')
            if p and p[0].strip() and not p[0].startswith('@'): mods.append(p[0].strip())
        return mods
    except: return []

def check_printer_9100(ip, timeout=2):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, 9100)); s.close(); return True
    except: return False

def check_upnp_igd(ip, timeout=3):
    try:
        msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
               'MAN: "ssdp:discover"\r\nMX: 2\r\n'
               'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        s.sendto(msg.encode(), (ip, 1900))
        try: d, _ = s.recvfrom(4096)
        except socket.timeout: s.close(); return None
        s.close()
        t = d.decode('utf-8','ignore')
        loc = re.search(r'LOCATION:\s*(.+)', t, re.I)
        if not loc: return None
        return {'location': loc.group(1).strip()}
    except: return None

# ─── Параллельный аудит ───
def run_full_audit(ip):
    """Возвращает список найденных проблем"""
    res = []
    print(f"\n{C.DIM}Параллельные проверки...{C.RESET}")

    tasks = [
        ('TLS 443',      lambda: check_tls_cert(ip, 443)),
        ('Headers 80',   lambda: check_http_headers(ip, 80, False)),
        ('Headers 443',  lambda: check_http_headers(ip, 443, True)),
        ('Panels 80',    lambda: check_exposed_panels(ip, 80, False)),
        ('Panels 8080',  lambda: check_exposed_panels(ip, 8080, False)),
        ('Git 80',       lambda: check_git_exposure(ip, 80, False)),
        ('NFS',          lambda: check_nfs_exports(ip)),
        ('rsync',        lambda: check_rsync_modules(ip, 873)),
        ('K8s',          lambda: check_k8s_api(ip, 6443)),
        ('SMB',          lambda: check_smb_shares(ip)),
        ('EternalBlue',  lambda: check_eternalblue(ip)),
        ('Redis',        lambda: check_redis(ip)),
        ('MongoDB',      lambda: check_mongodb(ip)),
        ('Elastic',      lambda: check_elasticsearch(ip)),
    ]

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(fn): (name, fn) for name, fn in tasks}
        for fut in as_completed(futs):
            name, _ = futs[fut]
            try:
                v = fut.result()
                if not v: continue
                if name == 'TLS 443':
                    print(f"  {C.BOLD}TLS:{C.RESET} {v['version']} · {v['cipher']}")
                    print(f"    CN: {v['subject_cn']} · Издатель: {v['issuer_cn']}")
                    print(f"    До: {v['not_after']}")
                    if v['weak']:
                        print(f"    {C.RED}⚠ {', '.join(v['weak'])}{C.RESET}")
                        res.append(('TLS', ', '.join(v['weak'])))
                elif 'Headers' in name:
                    port = name.split()[1]
                    if v['missing']:
                        print(f"  {C.YELLOW}Headers [{port}]:{C.RESET} нет: {', '.join(v['missing'])}")
                        res.append(('Headers', f"{port}: {', '.join(v['missing'])}"))
                elif 'Panels' in name and v:
                    for path, pname, st in v[:6]:
                        print(f"  {C.YELLOW}⚠{C.RESET} {pname} → {path} [{st}]")
                        res.append(('Panel', f'{pname} {path}'))
                elif name == 'Git 80' and v:
                    print(f"  {C.RED}⚠ .git: {v}{C.RESET}")
                    res.append(('.git', str(v)))
                elif name == 'EternalBlue' and v:
                    print(f"  {C.RED}⚠ MS17-010: {v}{C.RESET}")
                    res.append(('SMB', v))
                elif v not in (True, [], {}, '') and isinstance(v, (str, list)):
                    print(f"  {C.YELLOW}⚠{C.RESET} {name}: {v}")
                    res.append((name, str(v)))
            except Exception as e:
                print(f"  {C.RED}{name}: ошибка {e}{C.RESET}")
    return res
