import socket, ssl, re, threading, time
from .config import C, CRAWL_PATHS, PANELS
from .utils import progress_line, progress_end

def http_get(ip, port, path, https=False, timeout=4, max_bytes=50000):
    try:
        if https:
            ctx = ssl._create_unverified_context()
            s = socket.socket(); s.settimeout(timeout)
            s = ctx.wrap_socket(s, server_hostname=ip)
        else:
            s = socket.socket(); s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\n"
                   f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode())
        buf = b''
        while len(buf) < max_bytes:
            try:
                c = s.recv(4096)
                if not c: break
                buf += c
            except socket.timeout: break
        s.close()
        text = buf.decode('utf-8','ignore')
        if '\r\n\r\n' in text: h,b = text.split('\r\n\r\n',1)
        elif '\n\n' in text: h,b = text.split('\n\n',1)
        else: return (None, {}, text)
        lines = h.split('\n')
        m = re.match(r'HTTP/\d\.\d\s+(\d+)', lines[0].strip())
        st = int(m.group(1)) if m else 0
        hd = {}
        for l in lines[1:]:
            if ':' in l:
                k,v = l.split(':',1); hd[k.strip().lower()] = v.strip()
        return (st, hd, b)
    except: return (None, {}, '')

def http_post(ip, port, path, data, https=False, timeout=5):
    try:
        if https:
            ctx = ssl._create_unverified_context()
            s = socket.socket(); s.settimeout(timeout)
            s = ctx.wrap_socket(s, server_hostname=ip)
        else:
            s = socket.socket(); s.settimeout(timeout)
        s.connect((ip, port))
        body = data.encode() if isinstance(data,str) else data
        req = (f"POST {path} HTTP/1.1\r\nHost: {ip}:{port}\r\n"
               f"Content-Type: text/xml; charset=\"utf-8\"\r\n"
               f"SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        s.sendall(req)
        resp = b''; s.settimeout(3)
        while len(resp) < 10000:
            try:
                c = s.recv(4096)
                if not c: break
                resp += c
            except socket.timeout: break
            except: break
        s.close()
        return resp.decode('utf-8','ignore')
    except Exception as e: return str(e)

def extract_page_info(html):
    info = {'title':'','desc':'','h1':'','links':[],'text':''}
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I|re.S)
    if m: info['title'] = re.sub(r'\s+',' ',m.group(1)).strip()[:120]
    m = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.I)
    if m: info['desc'] = m.group(1).strip()[:200]
    m = re.search(r'<h1[^>]*>(.*?)</h1>', html, re.I|re.S)
    if m: info['h1'] = re.sub(r'<[^>]+>','',m.group(1)).strip()[:120]
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
        hr = m.group(1)
        if hr.startswith(('http','/','#','//')): info['links'].append(hr)
    info['links'] = list(dict.fromkeys(info['links']))[:30]
    t = re.sub(r'<script[^>]*>.*?</script>','',html,flags=re.S|re.I)
    t = re.sub(r'<style[^>]*>.*?</style>','',t,flags=re.S|re.I)
    t = re.sub(r'<[^>]+>',' ',t); t = re.sub(r'\s+',' ',t).strip()
    info['text'] = t[:500]
    return info

def crawl_site(ip, port, https=False, timeout=4):
    scheme = 'https' if https else 'http'
    print(f"\n{C.BOLD}{C.CYAN}[Краул]{C.RESET} {scheme}://{ip}:{port}\n")
    st, hd, bd = http_get(ip, port, '/', https, timeout)
    if st is None: print(f"  {C.RED}✗ нет ответа{C.RESET}"); return
    info = extract_page_info(bd)
    print(f"  {C.GREEN}✓{C.RESET} / → {C.BOLD}{st}{C.RESET} ({len(bd)} б)")
    if hd.get('server'): print(f"    {C.DIM}Server: {hd['server']}{C.RESET}")
    if hd.get('x-powered-by'): print(f"    {C.DIM}X-Powered-By: {hd['x-powered-by']}{C.RESET}")
    if info['title']: print(f"    {C.BOLD}Title:{C.RESET} {info['title']}")
    if info['h1']: print(f"    {C.BOLD}H1:{C.RESET} {info['h1']}")
    for path in CRAWL_PATHS:
        st,_,bd = http_get(ip, port, path, https, timeout=3, max_bytes=20000)
        if st and st < 400:
            print(f"  {C.GREEN}{st}{C.RESET} {path:<22} {C.DIM}{len(bd)} б{C.RESET}")
            if path.startswith('/.git') or path == '/.env' or path.endswith('.sql'):
                print(f"      {C.RED}⚠️  УТЕЧКА!{C.RESET}")

def probe_web_port(ip, port, timeout=2):
    try:
        ctx = ssl._create_unverified_context()
        s = socket.socket(); s.settimeout(timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip); ss.connect((ip, port))
        ss.sendall(f'GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode())
        d = ss.recv(64); ss.close()
        if d.startswith(b'HTTP/'): return 'https'
    except: pass
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        s.sendall(f'GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode())
        d = s.recv(64); s.close()
        if d.startswith(b'HTTP/'): return 'http'
    except: pass
    return None

def auto_find_web_ports(ip, ports, threads=100, timeout=2):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    print(f"\n{C.BOLD}[Веб-порты]{C.RESET} {len(ports)} портов...\n")
    found = []; done = 0; total = len(ports)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe_web_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            done += 1; port = futs[fut]; sc = fut.result()
            if sc:
                progress_end()
                print(f"  {C.GREEN}✓{C.RESET} {sc.upper():<6} {port}")
                found.append((port, sc))
            else:
                progress_line(f"[{done}/{total}] {done*100//total}% · найдено {len(found)}")
    progress_end()
    return found
