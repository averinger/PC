import os, time, datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import C, WHITELIST_FILE, BASELINE_FILE
from .utils import (header, ask, pause, ping, get_local_ip, load_json, save_json,
                    progress_line, progress_end)
from .network import identify_device, oui_lookup

def save_baseline():
    local = get_local_ip()
    if not local: print(f"{C.RED}Нет IP{C.RESET}"); return
    prefix = '.'.join(local.split('.')[:3])
    ips = [f"{prefix}.{i}" for i in range(1,255)]
    alive = []; done = 0
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(ping, ip, 1): ip for ip in ips}
        for fut in as_completed(futs):
            done += 1
            if fut.result(): alive.append(futs[fut])
            progress_line(f"{done}/254 · живых {len(alive)}")
    progress_end()
    bl = {'saved': time.time(), 'local_ip': local, 'devices': {}}
    for ip in alive:
        try:
            info = identify_device(ip)
            bl['devices'][ip] = {
                'mac': info['mac'],
                'name': info['ssdp_friendly'] or info['hostname'] or '',
                'type': info['type'],
            }
        except: pass
    save_json(BASELINE_FILE, bl)
    print(f"{C.GREEN}✓ Baseline: {len(alive)} устройств{C.RESET}")

def check_against_baseline():
    bl = load_json(BASELINE_FILE, {})
    if not bl: print(f"{C.YELLOW}Нет baseline{C.RESET}"); return
    local = get_local_ip()
    if not local: return
    prefix = '.'.join(local.split('.')[:3])
    ips = [f"{prefix}.{i}" for i in range(1,255)]
    alive = []; done = 0
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(ping, ip, 1): ip for ip in ips}
        for fut in as_completed(futs):
            done += 1
            if fut.result(): alive.append(futs[fut])
            progress_line(f"{done}/254 · живых {len(alive)}")
    progress_end()
    old = set(bl.get('devices',{}).keys()); new = set(alive)
    wl = load_json(WHITELIST_FILE, {})
    added = new - old; removed = old - new
    print()
    if added:
        print(f"{C.YELLOW}🆕 Новые:{C.RESET}")
        for ip in sorted(added):
            try:
                info = identify_device(ip)
                name = info['ssdp_friendly'] or info['hostname'] or '?'
                mac = info['mac'] or '—'
            except: name = '?'; mac = '—'
            mark = f" {C.GREEN}(whitelist){C.RESET}" if ip in wl else f" {C.RED}⚠ НЕ В WHITELIST{C.RESET}"
            print(f"  {ip}  {mac}  {name}{mark}")
    if removed:
        print(f"\n{C.DIM}Исчезли:{C.RESET}")
        for ip in sorted(removed): print(f"  {ip}")
    if not added and not removed: print(f"{C.GREEN}✓ Без изменений{C.RESET}")

def menu_whitelist():
    header("WHITELIST")
    wl = load_json(WHITELIST_FILE, {})
    if wl:
        print(f"{C.BOLD}Доверенные ({len(wl)}):{C.RESET}")
        for ip, d in wl.items(): print(f"  {C.GREEN}•{C.RESET} {ip}  {C.DIM}{d.get('note','')}{C.RESET}")
    else: print(f"{C.DIM}Пуст{C.RESET}")
    print(f"\n  1) Добавить\n  2) Удалить\n  3) Очистить\n  0) Назад")
    ch = ask("Выбор: ")
    if ch == '1':
        ip = ask("IP: "); note = ask("Заметка: ")
        wl[ip] = {'note':note,'added':time.time()}
        save_json(WHITELIST_FILE, wl)
        print(f"{C.GREEN}✓{C.RESET}")
    elif ch == '2':
        ip = ask("IP: ")
        if ip in wl: del wl[ip]; save_json(WHITELIST_FILE, wl); print(f"{C.GREEN}✓{C.RESET}")
    elif ch == '3':
        if ask("Точно? (y/N): ").lower() == 'y':
            save_json(WHITELIST_FILE, {}); print(f"{C.GREEN}✓{C.RESET}")
    pause()

def menu_monitoring():
    header("МОНИТОРИНГ СЕТИ")
    print("  1) Сохранить baseline\n  2) Проверить изменения\n  3) Инфо\n  0) Назад")
    ch = ask("Выбор: ")
    if ch == '1': save_baseline()
    elif ch == '2': check_against_baseline()
    elif ch == '3':
        bl = load_json(BASELINE_FILE, {})
        if bl:
            print(f"\nBaseline: {datetime.datetime.fromtimestamp(bl.get('saved',0)).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Устройств: {len(bl.get('devices',{}))}")
        else: print(f"{C.DIM}Нет baseline{C.RESET}")
    pause()
