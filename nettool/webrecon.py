import socket
import concurrent.futures
import dns.resolver
import dns.exception
import whois
import ipaddress
from .config import C
from .utils import header, ask, pause, progress_line, progress_end

SUBDOMAINS = [
    "www", "mail", "admin", "dev", "api", "test", "blog", "webmail", 
    "ns1", "ns2", "smtp", "vpn", "ftp", "portal", "secure", "login", 
    "cdn", "static", "img", "support", "store", "app", "dashboard"
]

def is_ip(target):
    """Проверяет, является ли цель IP-адресом"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def get_dns_records(domain):
    records = {'A': [], 'MX': [], 'NS': [], 'TXT': []}
    try:
        # configure=False спасает от ошибки /etc/resolv.conf
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 2
        resolver.lifetime = 2

        try:
            for rdata in resolver.resolve(domain, 'A'):
                records['A'].append(rdata.address)
        except: pass

        try:
            for rdata in resolver.resolve(domain, 'MX'):
                records['MX'].append(f"{rdata.preference} {rdata.exchange}")
        except: pass

        try:
            for rdata in resolver.resolve(domain, 'NS'):
                records['NS'].append(str(rdata.target))
        except: pass

        try:
            for rdata in resolver.resolve(domain, 'TXT'):
                records['TXT'].append(str(rdata).strip('"'))
        except: pass
    except Exception as e:
        print(f"  {C.RED}Ошибка DNS: {e}{C.RESET}")

    return records

def get_whois_info(target):
    try:
        w = whois.whois(target)
        return {
            'registrar': w.get('registrar'),
            'creation_date': w.get('creation_date'),
            'expiration_date': w.get('expiration_date'),
            'name_servers': w.get('name_servers'),
            'org': w.get('org'),
            'country': w.get('country')
        }
    except Exception as e:
        return {'error': str(e)}

def check_subdomain(args):
    domain, sub = args
    full = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(full)
        return (full, ip)
    except Exception:
        return None

def find_subdomains(domain, threads=20):
    found = []
    total = len(SUBDOMAINS)
    done = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(check_subdomain, (domain, sub)): sub for sub in SUBDOMAINS}
            for fut in concurrent.futures.as_completed(futs):
                done += 1
                res = fut.result()
                if res:
                    progress_end()
                    print(f"  {C.GREEN}✓{C.RESET} {res[0]:<30} {C.DIM}→ {res[1]}{C.RESET}")
                    found.append(res)
                else:
                    progress_line(f"[{done}/{total}] сканирую поддомены...")
        progress_end()
    except Exception as e:
        print(f"  {C.RED}Ошибка потоков: {e}{C.RESET}")
    return found

def menu_webrecon():
    header("РАЗВЕДКА ДОМЕНА / IP (WEB RECON)")
    target = ask("Домен или IP: ").strip()
    if not target:
        pause()
        return
    
    target_is_ip = is_ip(target)
    
    try:
        # 1. Поиск IP
        print(f"\n{C.BOLD}[1] Информация о цели{C.RESET}")
        if target_is_ip:
            print(f"  {C.GREEN}✓{C.RESET} Цель: IP-адрес {C.CYAN}{target}{C.RESET}")
            try:
                rev = socket.gethostbyaddr(target)
                print(f"  PTR-запись: {C.DIM}{rev[0]}{C.RESET}")
            except: pass
        else:
            ip = socket.gethostbyname(target)
            print(f"  {C.GREEN}✓{C.RESET} {target} → {C.CYAN}{ip}{C.RESET}")

        # 2. DNS-записи (только для доменов)
        if not target_is_ip:
            print(f"\n{C.BOLD}[2] DNS Записи{C.RESET}")
            dns_records = get_dns_records(target)
            for r_type, values in dns_records.items():
                if values:
                    print(f"  {C.YELLOW}{r_type}{C.RESET}:")
                    for v in values:
                        print(f"    {C.DIM}-{C.RESET} {v}")
                else:
                    print(f"  {C.DIM}{r_type}: нет записей{C.RESET}")
        else:
            print(f"\n{C.BOLD}[2] DNS Записи{C.RESET}")
            print(f"  {C.DIM}Пропущено (цель — IP-адрес){C.RESET}")

        # 3. WHOIS
        print(f"\n{C.BOLD}[3] WHOIS Информация{C.RESET}")
        print(f"  {C.DIM}Запрос к WHOIS-серверу...{C.RESET}")
        whois_info = get_whois_info(target)
        if 'error' in whois_info:
            print(f"  {C.RED}❌ Ошибка WHOIS: {whois_info['error']}{C.RESET}")
        else:
            if whois_info.get('org'): print(f"  Организация: {C.CYAN}{whois_info['org']}{C.RESET}")
            if whois_info.get('country'): print(f"  Страна: {C.CYAN}{whois_info['country']}{C.RESET}")
            if whois_info.get('registrar'): print(f"  Регистратор: {C.CYAN}{whois_info['registrar']}{C.RESET}")
            if whois_info.get('creation_date'): print(f"  Создан: {C.CYAN}{whois_info['creation_date']}{C.RESET}")
            if whois_info.get('expiration_date'): print(f"  Истекает: {C.CYAN}{whois_info['expiration_date']}{C.RESET}")
            
            ns = whois_info.get('name_servers')
            if ns:
                if isinstance(ns, list):
                    print(f"  NS-серверы: {C.CYAN}{', '.join(ns)}{C.RESET}")
                else:
                    print(f"  NS-серверы: {C.CYAN}{ns}{C.RESET}")

        # 4. Поиск поддоменов (только для доменов)
        if not target_is_ip:
            print(f"\n{C.BOLD}[4] Поиск поддоменов ({len(SUBDOMAINS)} шт){C.RESET}")
            if ask("Сканировать поддомены? (y/N): ").lower() == 'y':
                found = find_subdomains(target, threads=20)
                if not found:
                    print(f"  {C.DIM}Поддомены не найдены.{C.RESET}")
            else:
                print(f"  {C.DIM}Пропущено.{C.RESET}")
        else:
            print(f"\n{C.BOLD}[4] Поиск поддоменов{C.RESET}")
            print(f"  {C.DIM}Пропущено (цель — IP-адрес){C.RESET}")
            
    except Exception as e:
        print(f"\n{C.RED}Критическая ошибка: {e}{C.RESET}")
    
    pause()
