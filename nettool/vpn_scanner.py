import urllib.request
import socket
import base64
import json
import re
import time
import asyncio
import sys
import os
import threading
import concurrent.futures
from urllib.parse import urlparse
from .config import C
from .utils import header, ask, pause

SOURCES = [
    # MatinGhanbari (обновление каждые 15 мин)
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    
    # Sevcator (vless, vmess, trojan, ss)
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vm.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/tr.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt",
    
    # Delta-Kronecker (автосбор и тест через xray)
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/vless.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/trojan.txt",
    
    # Barry-far / longlon (обновление каждые 10 мин)
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    
    # Hans-thomas
    "https://raw.githubusercontent.com/hans-thomas/v2ray-subscription/master/servers.txt",
    
    # ShatakVPN ConfigForge
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/light.txt",
    
    # Geek-spot Free-Config
    "https://raw.githubusercontent.com/geek-spot/Free-Config/main/vmess",
    "https://raw.githubusercontent.com/geek-spot/Free-Config/main/vless",
    "https://raw.githubusercontent.com/geek-spot/Free-Config/main/trojan",
    
    # AvenCores / Goida
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/goida-vpn-configs.txt",
    
    # CDN (резерв)
    "https://cdn.jsdelivr.net/gh/xiaoji235/airport-free/v2ray.txt",
]

_print_lock = threading.Lock()

def fetch_source_parallel(url, name, timeout=12, max_size=10*1024*1024):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = bytearray()
            start = time.time()
            last_update = 0
            while len(data) < max_size:
                if time.time() - start > timeout:
                    with _print_lock:
                        sys.stdout.write(f"\r  {C.RED}✗ {name}: таймаут{C.RESET}\n")
                        sys.stdout.flush()
                    return ""
                try:
                    chunk = resp.read(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                if time.time() - last_update > 0.5:
                    last_update = time.time()
                    with _print_lock:
                        sys.stdout.write(f"\r  {C.DIM}↓ {name}: {len(data)//1024} КБ{C.RESET}")
                        sys.stdout.flush()
            elapsed = time.time() - start
            text = data.decode('utf-8', errors='ignore')
            with _print_lock:
                sys.stdout.write(f"\r  {C.GREEN}✓ {name}: {len(data)//1024} КБ за {elapsed:.1f}s{C.RESET}          \n")
                sys.stdout.flush()
            return text
    except Exception as e:
        with _print_lock:
            sys.stdout.write(f"\r  {C.RED}✗ {name}: {str(e)[:40]}{C.RESET}          \n")
            sys.stdout.flush()
        return ""

def decode_if_base64(text):
    if '://' in text:
        return text
    try:
        cleaned = re.sub(r'\s+', '', text)
        decoded = base64.b64decode(cleaned).decode('utf-8', errors='ignore')
        if '://' in decoded:
            return decoded
    except Exception:
        pass
    return text

def extract_host_port(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None, None
    try:
        if line.startswith('vmess://'):
            b64 = line[8:]
            b64 += '=' * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8'))
            return data.get('add'), int(data.get('port')) if data.get('port') else None
        if '://' not in line:
            return None, None
        rest = line.split('://', 1)[1].split('#', 1)[0].split('?', 1)[0]
        if '@' in rest:
            rest = rest.rsplit('@', 1)[1]
        if ':' in rest:
            host, port = rest.rsplit(':', 1)
            if port.isdigit():
                return host, int(port)
    except Exception:
        pass
    return None, None

def draw_bar(done, total, ok, start_time, width=32):
    pct = (done / total) if total > 0 else 0
    filled = int(pct * width)
    bar = '█' * filled + '░' * (width - filled)
    elapsed = time.time() - start_time
    speed = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / speed if speed > 0 else 0
    line = (f"\r  {C.GREEN}{bar}{C.RESET} "
            f"{C.BOLD}{pct*100:5.1f}%{C.RESET} "
            f"{C.DIM}{done}/{total}{C.RESET} "
            f"| {C.GREEN}OK:{ok}{C.RESET} "
            f"| {C.CYAN}{speed:>5.0f}/s{C.RESET} "
            f"| ETA {int(eta)}s ")
    sys.stdout.write(line)
    sys.stdout.flush()

async def test_one(host, port, line, sem, timeout):
    async with sem:
        try:
            start = time.perf_counter()
            # asyncio сам резолвит host асинхронно, не блокируя поток
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            elapsed = (time.perf_counter() - start) * 1000
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return (line, elapsed)
        except Exception:
            return None

async def async_test_all(configs, max_ping, concurrency=300, timeout=1.5):
    sem = asyncio.Semaphore(concurrency)
    working = []
    total = len(configs)
    start_time = time.time()
    done_counter = [0]

    tasks = [test_one(h, p, line, sem, timeout) for line, h, p in configs]

    async def wrapper(coro):
        res = await coro
        done_counter[0] += 1
        if res and res[1] <= max_ping:
            working.append(res)
        if done_counter[0] % 3 == 0 or done_counter[0] == total:
            draw_bar(done_counter[0], total, len(working), start_time)
        return res

    await asyncio.gather(*[wrapper(t) for t in tasks])
    sys.stdout.write("\r" + " " * 90 + "\r")
    return working

def menu_vpn_scanner():
    header("VPN-СКАНЕР (GitHub → PING ≤ 120ms)")
    print(f"{C.DIM}Параллельная загрузка {len(SOURCES)} источников...{C.RESET}\n")

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        futs = {}
        for url in SOURCES:
            name = url.split('/')[-1] or url.split('/')[-2]
            futs[ex.submit(fetch_source_parallel, url, name)] = name
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()

    print(f"\n{C.BOLD}Парсинг конфигов...{C.RESET}")
    raw_set = set()
    for url in SOURCES:
        name = url.split('/')[-1] or url.split('/')[-2]
        raw = results.get(name, "")
        if raw:
            decoded = decode_if_base64(raw)
            for l in decoded.splitlines():
                l = l.strip()
                if '://' in l:
                    raw_set.add(l)

    raw_lines = list(raw_set)
    total_raw = len(raw_lines)
    print(f"  {C.DIM}Уникальных строк: {total_raw:,}{C.RESET}")

    configs = []
    seen = set()
    t0 = time.time()
    for i, line in enumerate(raw_lines, 1):
        h, p = extract_host_port(line)
        if h and p:
            key = (h, p)
            if key not in seen:
                seen.add(key)
                configs.append((line, h, p))
        if i % 5000 == 0 or i == total_raw:
            pct = i * 100 // total_raw
            filled = int(pct / 100 * 32)
            bar = '█' * filled + '░' * (32 - filled)
            elapsed = time.time() - t0
            speed = i / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r  {C.GREEN}{bar}{C.RESET} {pct:3d}% {i:,}/{total_raw:,} | {speed:>0.0f}/s | OK: {len(configs):,}")
            sys.stdout.flush()
    sys.stdout.write("\n")

    total = len(configs)
    print(f"\n  {C.GREEN}✓{C.RESET} Готово. Уникальных конфигов: {C.BOLD}{total:,}{C.RESET}")
    if total == 0:
        pause(); return

    limit = ask("\nМаксимальный пинг (мс) [120]: ")
    try: max_ping = int(limit) if limit else 120
    except: max_ping = 120

    conc = ask("Одновременных проверок [300]: ")
    try: concurrency = int(conc) if conc else 300
    except: concurrency = 300

    print(f"\n{C.BOLD}Проверяю TCP-пинг (лимит: {max_ping} мс)...{C.RESET}\n")
    start = time.time()
    try:
        working = asyncio.run(async_test_all(configs, max_ping, concurrency, timeout=1.5))
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Прервано.{C.RESET}")
        pause(); return

    elapsed = time.time() - start
    print(f"\n{C.BOLD}{C.GREEN}Готово за {elapsed:.1f}с. Рабочих (≤{max_ping} мс): {len(working)}{C.RESET}")

    if working:
        working.sort(key=lambda x: x[1])
        # Ищем папку Загрузки
        download_dir = os.path.expanduser("~/storage/downloads")
        if not os.path.exists(download_dir):
            download_dir = "/sdcard/Download"
        if not os.path.exists(download_dir):
            download_dir = "."
        
        # Файл 1: обычный список URI
        out_path = os.path.join(download_dir, "vpn_working.txt")
        
        # Файл 2: Base64-подписка (для Amnezia/v2rayNG/NekoBox)
        sub_path = os.path.join(download_dir, "vpn_sub.txt")
        
        try:
            # Пишем обычный список
            with open(out_path, 'w', encoding='utf-8') as f:
                for line, _ in working:
                    f.write(line + '\n')
            
            # Формируем Base64 от всего списка
            all_uris = "\n".join(line for line, _ in working)
            b64_sub = base64.b64encode(all_uris.encode('utf-8')).decode('ascii')
            
            with open(sub_path, 'w', encoding='utf-8') as f:
                f.write(b64_sub)
            
            print(f"\n{C.GREEN}✅ Список URI:  {out_path}{C.RESET}")
            print(f"{C.GREEN}✅ Base64-подписка: {sub_path}{C.RESET}")
            print(f"{C.DIM}  (используй vpn_sub.txt для импорта как подписку){C.RESET}")
        except Exception as e:
            print(f"{C.RED}Ошибка сохранения: {e}{C.RESET}")

        print(f"\n{C.BOLD}Топ-10 самых быстрых:{C.RESET}")
        for line, ping in working[:10]:
            proto = line.split('://')[0]
            print(f"  {C.CYAN}{ping:>6.1f} мс{C.RESET}  {C.YELLOW}[{proto}]{C.RESET}  {line[:60]}...")
    else:
        print(f"{C.YELLOW}Попробуй увеличить лимит пинга или обнови список позже.{C.RESET}")

    pause()
