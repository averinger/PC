import os, csv, datetime
from .config import C, REPORTS_DIR

def save_report_txt(ip, open_tcp, open_udp, risks, http_ports):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(REPORTS_DIR, f"scan_{ip.replace('.','_')}_{ts}.txt")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"NETTOOL REPORT\n{'='*60}\n")
            f.write(f"Target: {ip}\n")
            f.write(f"Time:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"--- TCP ({len(open_tcp)}) ---\n")
            for p, s in sorted(open_tcp): f.write(f"  {p:<6} {s}\n")
            if open_udp:
                f.write(f"\n--- UDP ({len(open_udp)}) ---\n")
                for p in sorted(open_udp): f.write(f"  {p}\n")
            if risks:
                f.write(f"\n--- RISKS ---\n")
                for p, r in risks: f.write(f"  [{p}] {r}\n")
            if http_ports:
                f.write(f"\n--- HTTP PORTS ---\n  {http_ports}\n")
        print(f"\n{C.DIM}Отчёт: {fname}{C.RESET}")
    except: pass

def save_report_csv(devices):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(REPORTS_DIR, f"devices_{ts}.csv")
    try:
        with open(fname, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP","MAC","Name","Vendor","Type","OS","SSDP"])
            for d in devices:
                name = d.get('ssdp_friendly') or d.get('hostname') or d.get('netbios') or ''
                w.writerow([d.get('ip',''), d.get('mac',''), name,
                            d.get('vendor') or '', d.get('type',''),
                            d.get('os',''), d.get('ssdp_server','')])
        print(f"\n{C.GREEN}✓ CSV: {fname}{C.RESET}")
    except Exception as e:
        print(f"{C.RED}Ошибка CSV: {e}{C.RESET}")

def menu_reports():
    from .utils import header, ask, pause, get_local_ip, ping, progress_line, progress_end
    from .network import identify_device, oui_lookup
    from concurrent.futures import ThreadPoolExecutor, as_completed
    header("ОТЧЁТЫ")
    print("  1) CSV устройств\n  2) Показать папку\n  3) Удалить всё\n  0) Назад")
    ch = ask("Выбор: ")
    if ch == '1':
        local = get_local_ip()
        if not local: pause(); return
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
        dev = []
        for ip in alive:
            try:
                info = identify_device(ip)
                info['vendor'] = oui_lookup(info['mac'])
                dev.append(info)
            except: pass
        save_report_csv(dev)
    elif ch == '2':
        try:
            fs = sorted(os.listdir(REPORTS_DIR))
            if not fs: print(f"{C.DIM}Пусто{C.RESET}")
            for f in fs[:30]:
                p = os.path.join(REPORTS_DIR, f)
                print(f"  {f}  {C.DIM}({os.path.getsize(p)} б){C.RESET}")
        except: pass
    elif ch == '3':
        if ask("Точно? (y/N): ").lower() == 'y':
            for f in os.listdir(REPORTS_DIR):
                try: os.remove(os.path.join(REPORTS_DIR, f))
                except: pass
            print(f"{C.GREEN}✓{C.RESET}")
    pause()
