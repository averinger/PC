import sys, time, os, subprocess
from .config import C, COMMON_PORTS, WEB_SCAN_PORTS
from .utils import (clear, header, ask, pause, resolve, parse_ports,
                    get_local_ip, suggest_threads, cpu_count,
                    check_external_tools, progress_end)
from .network import scan_network
from .scanner import run_scan
from .http_utils import auto_find_web_ports, crawl_site
from .ssh_brute import scan_network_for_ssh, _fast_ssh_brute
from .vuln import (run_full_audit, check_snmp_brute, check_smb_shares,
                   check_printer_9100, check_mongodb, check_elasticsearch,
                   check_memcached, check_postgres_default, check_redis,
                   check_http_basic, check_ftp_default, check_telnet_default)
from .shell_vectors import scan_shell_vectors
from .exploits import scan_all_exploits
from .iot import scan_iot
from .monitoring import menu_whitelist, menu_monitoring
from .reports import menu_reports
from .web_brute import menu_web_brute
from .router_brute import menu_router_brute
from .wordlists import menu_wordlists
from .exploit_runner import run_ps4_browser_exploit, run_tizen_sdb_exploit, run_android_adb_exploit
from .webrecon import menu_webrecon
from .vpn_scanner import menu_vpn_scanner
from .awg_gen import menu_awg_gen

try:
    from .config import HAS_PARAMIKO as _HP
except:
    _HP = False

def show_disclaimer():
    clear()
    print(f"""
{C.RED}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║                    ⚠️   ВНИМАНИЕ   ⚠️                     ║
╠══════════════════════════════════════════════════════════╣{C.RESET}
{C.RED}║  ТОЛЬКО для аудита СВОЕЙ локальной сети.                 ║
║  Чужие сети/устройства без разрешения — УГОЛОВНО.         ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")
    try: input(f"{C.BOLD}Enter если согласен: {C.RESET}")
    except: sys.exit(0)

def select_target():
    header("ВЫБОР ЦЕЛИ")
    print(f"{C.DIM}1) Ввести IP вручную   2) Сканировать сеть и выбрать{C.RESET}")
    mode = ask("Выбор [1]: ") or '1'
    if mode == '2':
        alive = scan_network()
        if not alive:
            print(f"{C.RED}Нет устройств{C.RESET}"); pause(); return None
        for i, ip in enumerate(sorted(alive, key=lambda x: tuple(map(int, x.split('.')))), 1):
            print(f"  [{i}] {ip}")
        raw = ask("Номер [1]: ")
        try: idx = int(raw) if raw else 1
        except: idx = 1
        if 1 <= idx <= len(alive):
            return sorted(alive, key=lambda x: tuple(map(int, x.split('.'))))[idx-1]
        return None
    h = ask("IP: ")
    return resolve(h) if h else None

def menu_scan():
    header("СКАНИРОВАТЬ IP")
    ip = select_target()
    if not ip: return
    print("\n  1) Топ-42  2) 1-1024  3) 1-65535  4) Свой")
    ch = ask("Выбор [1]: ") or '1'
    if ch == '1': ports = COMMON_PORTS
    elif ch == '2': ports = list(range(1,1025))
    elif ch == '3': ports = list(range(1,65536))
    elif ch == '4':
        ports = parse_ports(ask("Порты: "))
        if not ports: pause(); return
    else: return
    rec = suggest_threads()
    raw = ask(f"Потоков [{rec}]: ")
    try: threads = max(1, min(int(raw) if raw else rec, 800))
    except: threads = rec
    raw = ask("Таймаут [1.5]: ")
    try: timeout = float(raw) if raw else 1.5
    except: timeout = 1.5
    deep = ask("Глубокая проверка? (y/N): ").lower() == 'y'
    do_udp = ask("UDP? (y/N): ").lower() == 'y'
    auto = ask("Авто-краул? (y/N): ").lower() == 'y'
    jit = ask("Jitter? (y/N): ").lower() == 'y'
    try:
        run_scan(ip, ports, threads, timeout, do_udp, deep, auto, jit)
    except KeyboardInterrupt: progress_end()
    pause()

def menu_crawl():
    header("ВЕБ-КРАУЛЕР")
    ip = select_target()
    if not ip: return
    print("\n  1) Быстро  2) Полно")
    m = ask("Выбор [2]: ") or '2'
    ports = WEB_SCAN_PORTS if m == '2' else [80,443,3000,5000,8000,8080,8443,8888,9000,9090]
    try:
        found = auto_find_web_ports(ip, ports, threads=100)
        if not found: print(f"{C.RED}Нет{C.RESET}"); pause(); return
        print(f"\n{C.GREEN}Найдено: {len(found)}{C.RESET}")
        for p, s in found: print(f"  {s}://{ip}:{p}")
        if ask("Краулить? (y/N): ").lower() == 'y':
            for p, s in found:
                try: crawl_site(ip, p, https=(s=='https'))
                except Exception as e: print(f"{C.RED}{e}{C.RESET}")
    except KeyboardInterrupt: progress_end()
    pause()

def menu_ssh_all():
    header("SSH — БРУТФОРС")
    print(f"{C.DIM}1) Ввести IP вручную   2) Сканировать сеть{C.RESET}")
    mode = ask("Выбор [1]: ") or '1'
    if mode == '2':
        hosts = scan_network_for_ssh()
        if not hosts: print(f"{C.RED}SSH не найдено{C.RESET}"); pause(); return
        for i, (hip, hp, hb) in enumerate(hosts, 1):
            print(f"  [{i}] {hip}:{hp}  {C.DIM}{hb[:60]}{C.RESET}")
        raw = ask("Номер [1]: ")
        try: idx = int(raw) if raw else 1
        except: idx = 1
        if not (1 <= idx <= len(hosts)): return
        ip, port, _ = hosts[idx-1]
    else:
        h = ask("IP: ")
        if not h: return
        ip = resolve(h)
        if not ip: print(f"{C.RED}не резолвится{C.RESET}"); pause(); return
        raw = ask("Порт [22]: ")
        try: port = int(raw) if raw else 22
        except: port = 22

    print(f"\n{C.BOLD}Цель:{C.RESET} {ip}:{port}")
    raw_u = ask("Логины (Enter — стандартный список): ")
    if raw_u:
        users = [u.strip() for u in raw_u.split(',') if u.strip()]
    else:
        from .config import ROUTER_USERNAMES
        users = ROUTER_USERNAMES

    print(f"\n{C.BOLD}Словарь паролей:{C.RESET}")
    print("  1) Мутации базовых паролей + rockyou (стандарт)")
    print("  2) Загрузить из файла (~/nettool/wordlists)")
    print("  3) Ввести свои (через запятую)")

    wchoice = ask("Выбор [1]: ") or '1'
    wordlist_name = None
    custom_passwords = None

    if wchoice == '2':
        from .wordlists import list_available
        avail = list_available()
        if not avail:
            print(f"{C.RED}Папка wordlists пуста. Скачайте словари в меню 20.{C.RESET}")
            pause(); return
        for i, (name, size) in enumerate(avail, 1):
            print(f"  [{i}] {name:<35} {size//1024} КБ")
        raw = ask("Номер: ")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(avail):
                wordlist_name = avail[idx][0]
            else:
                return
        except:
            return
    elif wchoice == '3':
        raw_p = ask("Пароли (через запятую): ")
        custom_passwords = [p.strip() for p in raw_p.split(',') if p.strip()]
        if not custom_passwords:
            print(f"{C.RED}Пустой список.{C.RESET}"); pause(); return

    raw_t = ask("Потоков [20]: ")
    try: threads = max(1, min(int(raw_t) if raw_t else 20, 50))
    except: threads = 20
    raw_d = ask("Задержка [0]: ")
    try: delay = float(raw_d) if raw_d else 0
    except: delay = 0

    if ask(f"{C.RED}Только своя сеть. Начать? (y/N): {C.RESET}").lower() != 'y': return
    try:
        _fast_ssh_brute(ip, port, users, threads, delay, wordlist_name, custom_passwords)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Прервано{C.RESET}")
    pause()

def menu_vuln_routers():
    header("УЯЗВИМОСТИ · РОУТЕРЫ")
    ip = select_target()
    if not ip: return
    res = []
    snmp = check_snmp_brute(ip)
    if snmp:
        for c, v in snmp:
            print(f"  {C.YELLOW}⚠ SNMP '{c}': {v[:60]}{C.RESET}"); res.append(('SNMP', c))
    smb = check_smb_shares(ip)
    if smb: print(f"  {C.YELLOW}⚠ SMB: {smb}{C.RESET}"); res.append(('SMB', smb))
    for name, fn, port in [('Redis', check_redis, 6379), ('MongoDB', check_mongodb, 27017),
                            ('Elasticsearch', check_elasticsearch, 9200),
                            ('Memcached', check_memcached, 11211),
                            ('PostgreSQL', check_postgres_default, 5432)]:
        print(f"  {C.DIM}{name}...{C.RESET}", end=" ")
        try:
            v = fn(ip, port)
            if v: print(f"{C.RED}⚠ {v}{C.RESET}"); res.append((name, v))
            else: print(f"{C.GREEN}✓{C.RESET}")
        except: print(f"{C.GREEN}✓{C.RESET}")
    b = check_http_basic(ip)
    if b: res.append(('HTTP Basic', str(b)))
    f = check_ftp_default(ip)
    if f: res.append(('FTP', str(f)))
    t = check_telnet_default(ip)
    if t: res.append(('Telnet', str(t)))
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    if res:
        print(f"{C.RED}{C.BOLD}⚠ Найдено: {len(res)}{C.RESET}")
        for n, d in res: print(f"  {C.RED}•{C.RESET} {n}: {d}")
    else: print(f"{C.GREEN}✓ Чисто{C.RESET}")
    pause()

def menu_vuln_android():
    header("УЯЗВИМОСТИ · ANDROID")
    ip = select_target()
    if not ip: return
    from .exploits import check_android_adb
    r = check_android_adb(ip)
    if r: print(f"\n{C.RED}⚠ {r}{C.RESET}")
    else: print(f"\n{C.GREEN}✓ ADB не найден{C.RESET}")
    pause()

def menu_vuln_ios():
    header("УЯЗВИМОСТИ · iOS")
    ip = select_target()
    if not ip: return
    from .exploits import check_ios_device
    r = check_ios_device(ip)
    if r: print(f"\n{C.YELLOW}⚠ {r}{C.RESET}")
    else: print(f"\n{C.GREEN}✓ iOS-признаки не найдены{C.RESET}")
    pause()

def menu_vuln_tv():
    header("УЯЗВИМОСТИ · ТЕЛЕВИЗОРЫ (Samsung Tizen)")
    ip = select_target()
    if not ip: return
    from .exploits import check_samsung_tizen
    r = check_samsung_tizen(ip)
    if r: print(f"\n{C.RED}⚠ {r}{C.RESET}")
    else: print(f"\n{C.GREEN}✓ Tizen не найден{C.RESET}")
    pause()

def menu_vuln_ps():
    header("УЯЗВИМОСТИ · PLAYSTATION")
    ip = select_target()
    if not ip: return
    from .exploits import check_playstation
    r = check_playstation(ip)
    if r: print(f"\n{C.YELLOW}⚠ {r}{C.RESET}")
    else: print(f"\n{C.GREEN}✓ PlayStation не найден{C.RESET}")
    pause()

def menu_audit():
    header("РАСШИРЕННЫЙ АУДИТ")
    ip = select_target()
    if not ip: return
    res = run_full_audit(ip)
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    if res:
        print(f"{C.RED}⚠ Проблем: {len(res)}{C.RESET}")
        for n, d in res: print(f"  {C.RED}•{C.RESET} {n}: {d}")
    else: print(f"{C.GREEN}✓ Чисто{C.RESET}")
    pause()

def menu_info():
    header("ИНФО")
    ip = get_local_ip() or '—'
    print(f"  Локальный IP: {C.GREEN}{ip}{C.RESET}")
    if ip != '—': print(f"  Подсеть:      {C.GREEN}{'.'.join(ip.split('.')[:3])}.0/24{C.RESET}")
    try:
        out = subprocess.run(['ip','route'], capture_output=True, text=True).stdout
        for l in out.splitlines():
            if l.startswith('default'):
                print(f"  Шлюз:         {C.GREEN}{l.split()[2]}{C.RESET}"); break
    except: pass
    print(f"  Ядер CPU:     {C.GREEN}{cpu_count()}{C.RESET}")
    print(f"  Реком. потоки:{C.GREEN}{suggest_threads()}{C.RESET}")
    tools = check_external_tools()
    print(f"  paramiko:     {C.GREEN if _HP else C.RED}{'✓' if _HP else '✗'}{C.RESET}")
    for k in ('hydra','sshpass','showmount'):
        print(f"  {k:<13} {C.GREEN if tools.get(k) else C.RED}{'✓' if tools.get(k) else '✗'}{C.RESET}")
    print(f"\n{C.DIM}DNS: {'работает' if resolve('google.com') else 'сломан'}{C.RESET}")
    pause()

def main_menu():
    clear()
    print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════╗
║          NETTOOL v4.5 · FULL EDITION             ║
╚══════════════════════════════════════════════════╝{C.RESET}

  {C.BOLD}1{C.RESET})  Сканировать IP (порты, сервисы, отчёт)
  {C.BOLD}2{C.RESET})  Веб-краулер
  {C.BOLD}3{C.RESET})  SSH — брутфорс
  {C.BOLD}4{C.RESET})  Найти устройства в сети

  {C.BOLD}{C.MAGENTA}— УЯЗВИМОСТИ ПО КАТЕГОРИЯМ —{C.RESET}
  {C.BOLD}5{C.RESET})  Роутеры (SNMP, SMB, БД, FTP/Telnet)
  {C.BOLD}6{C.RESET})  Android (ADB, CVE-2026-0073)
  {C.BOLD}7{C.RESET})  iOS (обнаружение)
  {C.BOLD}8{C.RESET})  Телевизоры (Samsung Tizen)
  {C.BOLD}9{C.RESET})  PlayStation (обнаружение)
  {C.BOLD}10{C.RESET}) Расширенный аудит (TLS, панели, .git, NFS)

  {C.BOLD}{C.MAGENTA}— ИНСТРУМЕНТЫ —{C.RESET}
  {C.BOLD}11{C.RESET}) Whitelist
  {C.BOLD}12{C.RESET}) Мониторинг (baseline + изменения)
  {C.BOLD}13{C.RESET}) Отчёты и экспорт
  {C.BOLD}14{C.RESET}) Инфо (IP, шлюз, ядра, движки)
  {C.BOLD}15{C.RESET}) Векторы Shell (Telnet, UPnP, RCE)
  {C.BOLD}16{C.RESET}) Новые эксплойты (ADB, Tizen, PS, Zyxel, Wavlink)
  {C.BOLD}17{C.RESET}) IoT-протоколы (MQTT, CoAP)
  {C.BOLD}18{C.RESET}) HTTP/HTTPS Брутфорс (Basic/Digest)
  {C.BOLD}19{C.RESET}) Брут пароля роутера (Mercusys TDDP)
  {C.BOLD}20{C.RESET}) Словари паролей (скачать/обновить)
  {C.BOLD}21{C.RESET}) Запуск эксплойтов (PS4/Tizen/Android)
  {C.BOLD}22{C.RESET}) Разведка домена (DNS/WHOIS/Поддомены)
  {C.BOLD}23{C.RESET}) VPN-сканер (GitHub → PING ≤ 120ms)
  {C.BOLD}24{C.RESET}) Генератор AmneziaWG (WARP API)  {C.GREEN}←{C.RESET}
  {C.BOLD}0{C.RESET})  Выход
""")

def run():
    show_disclaimer()
    while True:
        main_menu()
        ch = ask("Выбор: ")
        try:
            if ch == '1': menu_scan()
            elif ch == '2': menu_crawl()
            elif ch == '3': menu_ssh_all()
            elif ch == '4': scan_network(); pause()
            elif ch == '5': menu_vuln_routers()
            elif ch == '6': menu_vuln_android()
            elif ch == '7': menu_vuln_ios()
            elif ch == '8': menu_vuln_tv()
            elif ch == '9': menu_vuln_ps()
            elif ch == '10': menu_audit()
            elif ch == '11': menu_whitelist()
            elif ch == '12': menu_monitoring()
            elif ch == '13': menu_reports()
            elif ch == '14': menu_info()
            elif ch == '15':
                ip = select_target()
                if ip: scan_shell_vectors(ip)
            elif ch == '16':
                ip = select_target()
                if ip: scan_all_exploits(ip)
            elif ch == '17':
                ip = select_target()
                if ip: scan_iot(ip)
            elif ch == '18':
                menu_web_brute()
            elif ch == '19':
                menu_router_brute()
            elif ch == '20':
                menu_wordlists()
            elif ch == '21':
                ip = select_target()
                if ip:
                    print(f"\n{C.BOLD}Выберите эксплойт:{C.RESET}")
                    print("  1) PS4 (Browser Exploit)")
                    print("  2) Samsung Tizen (SDB)")
                    print("  3) Android (ADB CVE-2026-0073)")
                    ex_choice = ask("Выбор [1]: ") or '1'
                    if ex_choice == '1': run_ps4_browser_exploit(ip)
                    elif ex_choice == '2': run_tizen_sdb_exploit(ip)
                    elif ex_choice == '3': run_android_adb_exploit(ip)
            elif ch == '22':
                menu_webrecon()
            elif ch == '23':
                menu_vpn_scanner()
            elif ch == '24':
                menu_awg_gen()
            elif ch in ('0','q','exit'):
                print(f"\n{C.CYAN}Пока!{C.RESET}\n"); break
            else:
                print(f"{C.RED}Не понял{C.RESET}"); time.sleep(0.7)
        except KeyboardInterrupt:
            progress_end()
            print(f"\n{C.YELLOW}Прервано{C.RESET}"); time.sleep(0.5)
        except Exception as e:
            progress_end()
            print(f"\n{C.RED}Ошибка: {type(e).__name__}: {e}{C.RESET}")
            time.sleep(1)
