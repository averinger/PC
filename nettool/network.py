import os, re, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import C, OUI_DB
from .utils import ping, get_local_ip, progress_line, progress_end, ttl_os

# Пытаемся импортировать zeroconf для mDNS
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

def read_arp():
    o = {}
    try:
        with open('/proc/net/arp') as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p)>=4 and p[3]!='00:00:00:00:00:00': o[p[0]] = p[3]
    except: pass
    return o

def get_mac_for_ip(ip):
    a = read_arp()
    if ip in a and a[ip] != '00:00:00:00:00:00': return a[ip].lower()
    for cmd in (['ip','neigh','show',ip], ['/system/bin/ip','neigh','show',ip]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            m = re.search(r'lladdr\s+([0-9a-fA-F:]+)', r.stdout)
            if m and m.group(1) != '00:00:00:00:00:00': return m.group(1).lower()
        except: pass
    try:
        r = subprocess.run(['arp','-a',ip], capture_output=True, text=True, timeout=2)
        m = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', r.stdout)
        if m: return m.group(1).lower()
    except: pass
    return ''

def oui_lookup(mac):
    if not mac: return ''
    return OUI_DB.get(mac.upper()[:8], '')

def query_netbios(ip, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        pkt = (b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01')
        s.sendto(pkt, (ip, 137))
        d, _ = s.recvfrom(1024); s.close()
        if len(d) > 56:
            n = d[56:56+16].decode('ascii','ignore').strip('\x00').strip()
            if n: return n
    except: pass
    return None

def query_ssdp(ip, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
               'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
        s.sendto(msg.encode(), ('239.255.255.250', 1900))
        s.sendto(msg.encode(), (ip, 1900))
        out = []; t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                d, a = s.recvfrom(2048)
                if a[0] != ip: continue
                txt = d.decode('utf-8','ignore')
                sv = re.search(r'SERVER:\s*(.+)', txt, re.I)
                lo = re.search(r'LOCATION:\s*(.+)', txt, re.I)
                if sv: out.append(('server', sv.group(1).strip()))
                if lo: out.append(('location', lo.group(1).strip()))
            except socket.timeout: break
        s.close(); return out
    except: return []

def fetch_upnp_xml(location):
    try:
        m = re.match(r'http://([^/:]+)(?::(\d+))?(/.*)?$', location)
        if not m: return {}
        h, p, path = m.group(1), int(m.group(2) or 80), m.group(3) or '/'
        s = socket.socket(); s.settimeout(4); s.connect((h, p))
        s.sendall(f'GET {path} HTTP/1.0\r\nHost: {h}\r\nConnection: close\r\n\r\n'.encode())
        b = b''
        while len(b) < 30000:
            try:
                c = s.recv(4096)
                if not c: break
                b += c
            except: break
        s.close()
        x = b.decode('utf-8','ignore'); o = {}
        for tag in ['friendlyName','manufacturer','modelName','modelNumber']:
            mm = re.search(rf'<{tag}>(.*?)</{tag}>', x, re.I|re.S)
            if mm: o[tag] = re.sub(r'\s+',' ',mm.group(1)).strip()[:80]
        o['_has_igd'] = ('WANIPConnection' in x or 'WANPPPConnection' in x)
        o['_has_wps'] = ('WPS' in x or 'WLANConfiguration' in x)
        return o
    except: return {}

def guess_type(server, loc, friendly='', model=''):
    s = (server or '').lower(); l = (loc or '').lower()
    f = (friendly or '').lower(); m = (model or '').lower()
    if 'chromecast' in s or 'chromecast' in l: return 'Chromecast'
    if 'samsung' in s or 'samsung' in m: return 'Samsung TV'
    if 'tenda' in s or 'ac10' in s: return 'Tenda router'
    if 'igd' in l or 'internetgateway' in l: return 'Роутер'
    if 'printer' in s or 'print' in f: return 'Принтер'
    if 'windows' in s or 'microsoft' in s: return 'Windows'
    if 'lg' in s: return 'LG TV'
    if 'xiaomi' in s or 'mi ' in f: return 'Xiaomi'
    if 'sonos' in s or 'sonos' in f: return 'Sonos'
    if 'philips' in s or 'hue' in f: return 'Philips Hue'
    if 'synology' in s or 'synology' in f: return 'NAS'
    if 'espressif' in s or 'esp' in s: return 'ESP32/ESP8266'
    if 'raspberry' in m or 'raspberry' in f: return 'Raspberry Pi'
    return ''

def query_ps4(ip, timeout=3):
    """UDP 987 — фирменный discovery PS4/PS5"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        pkt = (b'SRCH * HTTP/1.1\r\n'
               b'device-discovery-protocol-version:00020020\r\n'
               b'client-type:PC\r\n'
               b'host-id:FFFFFFFFFFFFFFFF\r\n'
               b'host-type:PS4\r\n'
               b'host-name:nettool\r\n'
               b'host-request-port:997\r\n\r\n')
        s.sendto(pkt, (ip, 987))
        try:
            data, _ = s.recvfrom(1024)
            txt = data.decode('utf-8', 'ignore')
            if 'PS4' in txt or 'PS5' in txt:
                m = re.search(r'host-name:\s*([^\r\n]+)', txt, re.I)
                name = m.group(1).strip() if m else 'PlayStation'
                if 'PS5' in txt: return f'PS5 ({name})'
                return f'PS4 ({name})'
        except socket.timeout: pass
        s.close()
    except: pass
    return None

def guess_phone_model(ip, mac, hostname, ssdp_friendly, ssdp_model):
    for src in (ssdp_model, ssdp_friendly):
        if src:
            low = src.lower()
            for b in ('xiaomi','redmi','poco','samsung','galaxy','pixel','oneplus',
                      'huawei','honor','realme','oppo','vivo','iphone','ipad'):
                if b in low: return src
    if hostname:
        low = hostname.lower()
        for k in ('redmi','poco','galaxy','pixel','oneplus','honor','realme',
                  'oppo','vivo','iphone','ipad','android'):
            if k in low: return hostname
    return ''

# ══════════ mDNS Discovery ══════════
class MDNSListener(ServiceListener):
    def __init__(self, ip):
        self.ip = ip
        self.services = []
        
    def add_service(self, zc, type_, name):
        # Пропускаем мета-сервисы и некорректные типы
        if not type_.endswith(('._tcp.local.', '._udp.local.')):
            return
        if type_ == '_services._dns-sd._udp.local.':
            return
        try:
            info = zc.get_service_info(type_, name)
        except Exception:
            return
        if not info:
            return
        # Сверяем IP
        addrs = info.parsed_addresses()
        if self.ip not in addrs and info.server and not info.server.startswith(self.ip.split('.')[0]):
            return
        txt = {}
        if info.properties:
            for k, v in info.properties.items():
                try: txt[k.decode()] = v.decode()
                except: pass
        self.services.append({
            'type': type_,
            'name': name,
            'server': info.server,
            'txt': txt,
            'port': info.port,
        })
        
    def update_service(self, zc, type_, name): pass
    def remove_service(self, zc, type_, name): pass

def query_mdns(ip, timeout=3):
    if not HAS_ZEROCONF:
        return []
    zc = Zeroconf()
    listener = MDNSListener(ip)
    try:
        browser = ServiceBrowser(zc, "_services._dns-sd._udp.local.", listener)
        time.sleep(timeout)
    finally:
        zc.close()
    return listener.services

def identify_device(ip):
    i = {'ip':ip,'mac':'','hostname':'','netbios':'',
         'ssdp_server':'','ssdp_location':'','ssdp_friendly':'',
         'ssdp_manufacturer':'','ssdp_model':'','vendor':'','type':'','os':'',
         'mdns_services':[]}
    i['mac'] = get_mac_for_ip(ip)
    try: i['hostname'] = socket.gethostbyaddr(ip)[0]
    except: pass
    nb = query_netbios(ip, 1.5)
    if nb: i['netbios'] = nb
    for k, v in query_ssdp(ip, 2):
        if k == 'server': i['ssdp_server'] = v
        elif k == 'location': i['ssdp_location'] = v
    if i['ssdp_location']:
        up = fetch_upnp_xml(i['ssdp_location'])
        i['ssdp_friendly'] = up.get('friendlyName','')
        i['ssdp_manufacturer'] = up.get('manufacturer','')
        i['ssdp_model'] = up.get('modelName','')
    i['type'] = guess_type(i['ssdp_server'], i['ssdp_location'],
                            i['ssdp_friendly'], i['ssdp_model'])
    i['os'] = ttl_os(ip, 1)
    i['ps4'] = query_ps4(ip, 2)
    i['phone_model'] = guess_phone_model(ip, i['mac'], i['hostname'],
                                             i['ssdp_friendly'], i['ssdp_model'])
    # mDNS
    i['mdns_services'] = query_mdns(ip, timeout=3)
    if i['mdns_services']:
        for svc in i['mdns_services']:
            if 'android' in svc['type'].lower() or 'device-info' in svc['type'].lower():
                for key in ('model', 'md', 'ty'):
                    if key in svc['txt']:
                        i['phone_model'] = svc['txt'][key]
                        break
            if 'apple' in svc['type'].lower() or 'airplay' in svc['type'].lower():
                for key in ('model', 'am'):
                    if key in svc['txt']:
                        i['phone_model'] = svc['txt'][key]
                        break
        if any('android' in s['type'].lower() for s in i['mdns_services']):
            if not i['type']: i['type'] = 'Android'
        elif any('apple' in s['type'].lower() or 'airplay' in s['type'].lower() for s in i['mdns_services']):
            if not i['type']: i['type'] = 'iOS / Apple'
            
    return i

def scan_network():
    local = get_local_ip()
    if not local: print(f"{C.RED}❌ Нет IP{C.RESET}"); return []
    prefix = '.'.join(local.split('.')[:3])
    print(f"\n{C.DIM}Локальный IP: {local}{C.RESET}")
    print(f"{C.DIM}Сканирую {prefix}.0/24{C.RESET}\n")
    ips = [f"{prefix}.{i}" for i in range(1,255)]
    alive = []; done = 0
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(ping, ip, 1): ip for ip in ips}
        for fut in as_completed(futs):
            done += 1
            if fut.result(): alive.append(futs[fut])
            progress_line(f"ping sweep {done}/254 · живых {len(alive)}")
    progress_end()
    print(f"{C.GREEN}Живых: {len(alive)}{C.RESET}")
    if not alive: return []

    if not HAS_ZEROCONF:
        print(f"{C.YELLOW}⚠ zeroconf не установлен. mDNS не будет работать. Установи: pip install zeroconf{C.RESET}")

    for ip in sorted(alive, key=lambda x: tuple(map(int, x.split('.')))):
        info = identify_device(ip)
        mac = info['mac'] or '—'
        name = info['ssdp_friendly'] or info['hostname'] or info['netbios'] or '—'
        vendor = oui_lookup(info['mac']) or info['ssdp_manufacturer'] or '—'
        dev_type = info['type'] or '—'
        os_guess = info['os'] or '—'
        model_info = info.get('ps4') or info.get('phone_model') or ''
        mark = f" {C.CYAN}← ты{C.RESET}" if ip == local else ''

        print(f"\n  {C.BOLD}{C.GREEN}▶ {ip}{C.RESET}{mark}")
        print(f"    {C.DIM}MAC:{C.RESET}      {mac}")
        print(f"    {C.DIM}Имя:{C.RESET}      {name}")
        print(f"    {C.DIM}Произв.:{C.RESET}  {C.MAGENTA}{vendor}{C.RESET}")
        print(f"    {C.DIM}Тип:{C.RESET}      {C.YELLOW}{dev_type}{C.RESET}")
        print(f"    {C.DIM}OS:{C.RESET}       {C.DIM}{os_guess}{C.RESET}")
        if model_info:
            print(f"    {C.DIM}Модель:{C.RESET}   {C.CYAN}{model_info}{C.RESET}")
        if info.get('mdns_services'):
            svc_names = [s['type'].replace('._tcp.local.','').replace('._udp.local.','') for s in info['mdns_services'][:3]]
            print(f"    {C.DIM}Сервисы:{C.RESET}  {', '.join(svc_names)}")
        print(f"  {C.DIM}{'─'*54}{C.RESET}")
    return alive
