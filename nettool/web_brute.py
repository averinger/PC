import socket, ssl, base64, time, threading, queue
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from .config import C, WEB_SCAN_PORTS
from .utils import header, ask, pause, beep, progress_line, progress_end
from .http_utils import auto_find_web_ports

# Отключаем предупреждения SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_USERS = ["admin", "root", "user", "administrator", "test"]
DEFAULT_PASSWORDS = [
    "admin", "password", "1234", "12345", "123456", "root", "toor",
    "pass", "qwerty", "letmein", "guest", "changeme", "default"
]

def _try_auth(url, user, pw, auth_type="basic", timeout=5):
    """Пробует одну пару логин/пароль. Возвращает True только при реальном успехе."""
    try:
        if auth_type == "basic":
            auth = HTTPBasicAuth(user, pw)
        else:
            auth = HTTPDigestAuth(user, pw)
        r = requests.get(url, auth=auth, timeout=timeout, verify=False, allow_redirects=False)
        # Если сервер не отвечает 401 и не просит авторизацию — это не Basic/Digest
        if r.status_code != 401 and "www-authenticate" not in r.headers:
            return False
        # Успех — 200 OK или 302 (редирект после входа)
        if r.status_code in (200, 302):
            return True
    except requests.exceptions.RequestException:
        pass
    return False

def brute_http_auth(url, users=None, passwords=None, auth_type="basic", threads=5, delay=0.1):
    """Многопоточный перебор. Возвращает список найденных пар."""
    users = users or DEFAULT_USERS
    passwords = passwords or DEFAULT_PASSWORDS
    
    print(f"\n{C.BOLD}[HTTP Auth Brute]{C.RESET} {url}")
    print(f"  {C.DIM}Тип: {auth_type.upper()} | Логинов: {len(users)} | Паролей: {len(passwords)} | Потоков: {threads}{C.RESET}\n")
    
    found = []
    lock = threading.Lock()
    stop_flag = threading.Event()
    
    task_q = queue.Queue()
    for u in users:
        for p in passwords:
            task_q.put((u, p))
    
    total = len(users) * len(passwords)
    done = [0]
    
    def worker():
        while not stop_flag.is_set():
            try:
                u, p = task_q.get_nowait()
            except queue.Empty:
                return
            time.sleep(delay)
            ok = _try_auth(url, u, p, auth_type)
            with lock:
                done[0] += 1
                if ok:
                    found.append((u, p))
                    print(f"\n  {C.GREEN}{C.BOLD}🔓 НАЙДЕНО: {u}:{p}{C.RESET}")
                    beep()
                if done[0] % 5 == 0:
                    progress_line(f"[{done[0]}/{total}] проверено · найдено {len(found)}")
            task_q.task_done()
    
    threads_list = [threading.Thread(target=worker) for _ in range(threads)]
    for t in threads_list:
        t.start()
    for t in threads_list:
        t.join()
    
    progress_end()
    return found

def menu_web_brute():
    header("HTTP/HTTPS БРУТФОРС (Basic/Digest)")
    
    # Дисклеймер
    print(f"""{C.RED}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║  ⚠️  ВНИМАНИЕ: ТОЛЬКО ДЛЯ ТЕСТИРОВАНИЯ СВОИХ СИСТЕМ!  ║
║  Использование на чужих сайтах без разрешения —          ║
║  УГОЛОВНО НАКАЗУЕМ.                                     ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")
    if ask("Я подтверждаю, что тестирую свой ресурс (y/N): ").lower() != 'y':
        print(f"{C.YELLOW}Отменено.{C.RESET}")
        pause()
        return
    
    print(f"\n{C.BOLD}Выберите способ:{C.RESET}")
    print("  1) Ввести URL вручную")
    print("  2) Выбрать IP из сети (авто-поиск веб-портов)")
    
    mode = ask("Выбор [1]: ") or '1'
    
    url = None
    if mode == '1':
        raw = ask("URL (например, http://192.168.1.1/admin): ")
        if not raw:
            pause(); return
        if not raw.startswith(('http://', 'https://')):
            raw = 'http://' + raw
        url = raw
    elif mode == '2':
        ip = ask("IP цели: ")
        if not ip:
            pause(); return
        print(f"\n{C.DIM}Сканирую веб-порты на {ip}...{C.RESET}")
        found_ports = auto_find_web_ports(ip, WEB_SCAN_PORTS, threads=50, timeout=1.5)
        if not found_ports:
            print(f"{C.RED}Веб-порты не найдены.{C.RESET}")
            pause(); return
        print(f"\n{C.GREEN}Найдено портов: {len(found_ports)}{C.RESET}")
        for i, (p, scheme) in enumerate(found_ports, 1):
            print(f"  [{i}] {scheme}://{ip}:{p}")
        idx = ask("Номер порта (Enter — первый): ")
        try:
            n = int(idx) if idx else 1
            if 1 <= n <= len(found_ports):
                port, scheme = found_ports[n-1]
                url = f"{scheme}://{ip}:{port}"
            else:
                print(f"{C.RED}Неверный номер.{C.RESET}"); pause(); return
        except:
            port, scheme = found_ports[0]
            url = f"{scheme}://{ip}:{port}"
    else:
        return
    
    # Проверяем, требует ли URL реальную авторизацию (Basic/Digest)
    print(f"\n{C.DIM}Проверка {url}...{C.RESET}")
    try:
        r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
        
        # Если статус не 401 — это НЕ Basic/Digest. Скорее всего веб-форма или открытый доступ.
        if r.status_code != 401:
            print(f"{C.RED}❌ Сервер не использует Basic/Digest (статус {r.status_code}).{C.RESET}")
            print(f"{C.YELLOW}   Это веб-форма или открытый доступ. Брутфорс HTTP Auth не сработает.{C.RESET}")
            print(f"{C.DIM}   Для веб-форм используйте форму POST-запросов (или инструменты вроде Hydra).{C.RESET}")
            pause()
            return
        
        # Если 401 — смотрим, какой тип авторизации
        www = r.headers.get('WWW-Authenticate', '')
        if 'digest' in www.lower():
            auth_type = 'digest'
        else:
            auth_type = 'basic'
        print(f"{C.GREEN}✅ Требуется авторизация: {auth_type.upper()}{C.RESET}")
        
    except Exception as e:
        print(f"{C.RED}Ошибка подключения: {e}{C.RESET}")
        pause(); return
    
    print(f"\n{C.BOLD}Настройки перебора:{C.RESET}")
    raw_t = ask("Потоков [5]: ")
    try: threads = max(1, min(int(raw_t) if raw_t else 5, 20))
    except: threads = 5
    raw_d = ask("Задержка, сек [0.1]: ")
    try: delay = float(raw_d) if raw_d else 0.1
    except: delay = 0.1
    
    raw_u = ask("Логины (через запятую, Enter — стандартный): ")
    if raw_u:
        users = [u.strip() for u in raw_u.split(',') if u.strip()]
    else:
        users = DEFAULT_USERS
    
    raw_p = ask("Пароли (через запятую, Enter — стандартный): ")
    if raw_p:
        passwords = [p.strip() for p in raw_p.split(',') if p.strip()]
    else:
        passwords = DEFAULT_PASSWORDS
    
    print(f"\n{C.RED}Начинаю перебор... (Ctrl+C для остановки){C.RESET}")
    try:
        found = brute_http_auth(url, users, passwords, auth_type, threads, delay)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Прервано.{C.RESET}")
        pause(); return
    
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    if found:
        print(f"{C.GREEN}{C.BOLD}✅ НАЙДЕНО УЧЁТНЫХ ЗАПИСЕЙ: {len(found)}{C.RESET}")
        for u, p in found:
            print(f"  {C.GREEN}•{C.RESET} {u}:{p}")
    else:
        print(f"{C.YELLOW}❌ Пароли не подобраны.{C.RESET}")
    pause()
