import os, sys, time
import requests
import urllib3
from .config import C
from .utils import header, ask, pause, beep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WORDLISTS_DIR = os.path.expanduser("~/nettool/wordlists")
os.makedirs(WORDLISTS_DIR, exist_ok=True)

# ИСПРАВЛЕННЫЙ СПИСОК (стабильные ссылки)
WORDLIST_SOURCES = {
    # === Базовые (небольшие, быстрые) ===
    "10k-most-common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    "100k-most-used.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
    "darkweb2017-top10000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt",

    # === Крупные (миллионы строк) ===
    "1M-most-common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "xato-1M.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000000.txt",
    "ignis-10M.txt": "https://raw.githubusercontent.com/ignis-sec/Pwdb-Public/master/wordlists/ignis-10M.txt",
    "rockyou.txt": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",

    # === Русскоязычные ===
    "russian.txt": "https://raw.githubusercontent.com/vaginessa/Language-Password-Lists/master/russian.txt",
}

def _download(url, dest, timeout=30):
    try:
        print(f"  {C.DIM}Скачивание: {os.path.basename(dest)}{C.RESET}")
        r = requests.get(url, stream=True, timeout=timeout, verify=False)
        r.raise_for_status()
        total = int(r.headers.get('content-length', 0))
        downloaded = 0
        with open(dest, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = downloaded * 100 // total
                        sys.stdout.write(f"\r    {C.DIM}{pct}% ({downloaded//1024} КБ){C.RESET}")
                        sys.stdout.flush()
        sys.stdout.write("\r" + " " * 60 + "\r")
        print(f"  {C.GREEN}✅ Готово: {os.path.basename(dest)} ({os.path.getsize(dest)//1024} КБ){C.RESET}")
        return True
    except Exception as e:
        print(f"\n  {C.RED}❌ Ошибка: {e}{C.RESET}")
        if os.path.exists(dest):
            os.remove(dest)
        return False

def add_custom_wordlist(name, url):
    if not name.endswith('.txt'):
        name += '.txt'
    dest = os.path.join(WORDLISTS_DIR, name)
    if os.path.exists(dest):
        print(f"{C.YELLOW}Файл '{name}' уже существует. Перезаписать? (y/N): {C.RESET}", end="")
        if ask("").lower() != 'y':
            return False
    print(f"\n{C.BOLD}[Добавление словаря]{C.RESET} {name}")
    return _download(url, dest)

def ensure_wordlists(only_missing=True):
    header("ЗАГРУЗКА БАЗОВЫХ СЛОВАРЕЙ")
    print(f"  Папка: {C.DIM}{WORDLISTS_DIR}{C.RESET}\n")
    all_ok = True
    for name, url in WORDLIST_SOURCES.items():
        dest = os.path.join(WORDLISTS_DIR, name)
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            if only_missing:
                print(f"  {C.GREEN}✓{C.RESET} {name} уже есть ({os.path.getsize(dest)//1024} КБ)")
                continue
        if not _download(url, dest):
            all_ok = False
    return all_ok

def get_wordlist_path(name):
    p = os.path.join(WORDLISTS_DIR, name)
    if os.path.exists(p) and os.path.getsize(p) > 0:
        return p
    return None

def load_lines(name, max_lines=None):
    p = get_wordlist_path(name)
    if not p:
        return []
    lines = []
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                s = line.strip()
                if s:
                    lines.append(s)
                    if max_lines and len(lines) >= max_lines:
                        break
    except Exception:
        pass
    return lines

def list_available():
    out = []
    if os.path.isdir(WORDLISTS_DIR):
        for f in sorted(os.listdir(WORDLISTS_DIR)):
            p = os.path.join(WORDLISTS_DIR, f)
            if os.path.isfile(p):
                out.append((f, os.path.getsize(p)))
    return out

def menu_wordlists():
    header("СЛОВАРИ ПАРОЛЕЙ")
    avail = list_available()
    if avail:
        print(f"{C.BOLD}Доступные словари:{C.RESET}")
        for name, size in avail:
            print(f"  {C.GREEN}•{C.RESET} {name:<35} {size//1024} КБ")
    else:
        print(f"{C.DIM}Папка пуста.{C.RESET}")
    
    print(f"\n{C.BOLD}Действия:{C.RESET}")
    print("  1) Скачать все базовые словари")
    print("  2) Скачать только отсутствующие")
    print("  3) Скачать конкретный базовый словарь")
    print("  4) ➕ Добавить свой словарь по ссылке")
    print("  5) Показать размер папки")
    print("  0) Назад")
    
    ch = ask("Выбор [2]: ") or '2'
    
    if ch == '1':
        ensure_wordlists(only_missing=False)
    elif ch == '2':
        ensure_wordlists(only_missing=True)
    elif ch == '3':
        names = list(WORDLIST_SOURCES.keys())
        for i, n in enumerate(names, 1):
            print(f"  [{i}] {n}")
        raw = ask("Номер: ")
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(names):
                name = names[idx]
                dest = os.path.join(WORDLISTS_DIR, name)
                if os.path.exists(dest):
                    print(f"{C.YELLOW}Файл уже существует. Перезаписать? (y/N): {C.RESET}", end="")
                    if ask("").lower() != 'y':
                        pause(); return
                _download(WORDLIST_SOURCES[name], dest)
        except: pass
    elif ch == '4':
        print(f"\n{C.BOLD}[Свой словарь]{C.RESET}")
        url = ask("Ссылка на файл (raw .txt): ")
        if not url: pause(); return
        name = ask("Имя файла (например, mylist.txt): ")
        if not name: pause(); return
        if add_custom_wordlist(name, url):
            print(f"{C.GREEN}✅ Словарь добавлен.{C.RESET}")
        else:
            print(f"{C.RED}❌ Не удалось добавить.{C.RESET}")
    elif ch == '5':
        total = sum(s for _, s in avail)
        print(f"\n  Всего: {len(avail)} файлов, {total // (1024*1024)} МБ")
        for n, s in avail:
            print(f"  - {n}: {s//1024} КБ")
    
    pause()
