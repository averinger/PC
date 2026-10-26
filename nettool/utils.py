import os, sys, socket, subprocess, json, time, re
from .config import C, LOG_FILE, WHITELIST_FILE, TMPDIR

def clear(): os.system('clear')

def header(t):
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {t}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")

def ask(p):
    try: return input(f"{C.BOLD}{p}{C.RESET}").strip()
    except (KeyboardInterrupt, EOFError): print(); return ''

def pause(): input(f"\n{C.DIM}Enter → в меню...{C.RESET}")

def resolve(h):
    try: return socket.gethostbyname(h)
    except socket.gaierror: return None

def parse_ports(s):
    out = set()
    for p in s.replace(' ','').split(','):
        if not p: continue
        if '-' in p:
            try: a,b = p.split('-',1); out.update(range(int(a),int(b)+1))
            except: pass
        elif p.isdigit(): out.add(int(p))
    return sorted(out)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); ip = s.getsockname()[0]; s.close(); return ip
    except: return None

def progress_line(text):
    sys.stdout.write(f"{C.CLR}  {C.DIM}{text}{C.RESET}"); sys.stdout.flush()

def progress_end():
    sys.stdout.write(C.CLR); sys.stdout.flush()

def load_json(p, d=None):
    try:
        with open(p) as f: return json.load(f)
    except: return d if d is not None else {}

def save_json(p, d):
    try:
        with open(p, 'w') as f: json.dump(d, f, indent=2, ensure_ascii=False); return True
    except: return False

def ping(ip, timeout=1):
    try:
        r = subprocess.run(['ping','-c','1','-W',str(timeout),ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
        return r.returncode == 0
    except: return False

def ttl_os(ip, timeout=2):
    """Грубая OS-детекция по TTL"""
    try:
        r = subprocess.run(['ping','-c','1','-W',str(timeout),ip],
                           capture_output=True, text=True, timeout=timeout+1)
        m = re.search(r'ttl=(\d+)', r.stdout, re.I)
        if not m: return ''
        t = int(m.group(1))
        if t <= 64: return 'Linux/Unix'
        if t <= 128: return 'Windows'
        if t <= 255: return 'Cisco/BSD'
    except: pass
    return ''

def log(msg):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {msg}\n")
    except: pass

def beep():
    """Терминальный звонок на находку"""
    sys.stdout.write('\a'); sys.stdout.flush()

def jitter(base=0.05, spread=0.15):
    """Случайная задержка для обхода простых rate-limit"""
    import random
    time.sleep(base + random.random()*spread)

def check_external_tools():
    t = {}
    for name in ('hydra','sshpass','ssh','curl','showmount','nmap'):
        try:
            r = subprocess.run(['which',name], capture_output=True, text=True, timeout=2)
            t[name] = r.returncode == 0
        except: t[name] = False
    return t

def find_wordlist(name):
    from .config import HOME
    for c in [os.path.join(HOME,'wordlists',name),
              os.path.join(HOME,'SecLists','Passwords','Common-Credentials',name),
              os.path.join(HOME,'SecLists',name), os.path.join(HOME, name)]:
        if os.path.exists(c): return c
    return None

def check_whitelist(ip):
    wl = load_json(WHITELIST_FILE, {})
    if ip not in wl:
        print(f"{C.YELLOW}⚠ IP {ip} не в Whitelist.{C.RESET}")
        if ask("Добавить? (y/N): ").lower() != 'y':
            return False
        wl[ip] = {'note':'auto','added':time.time()}
        save_json(WHITELIST_FILE, wl)
    return True

def cpu_count():
    try: return os.cpu_count() or 4
    except: return 4

def suggest_threads():
    n = cpu_count()
    return 50 if n<=2 else 100 if n<=4 else 150 if n<=6 else 200
