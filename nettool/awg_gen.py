import os
import json
import time
import base64
import urllib.request
import ssl
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from .config import C
from .utils import header, ask, pause

# Официальный API Cloudflare WARP для регистрации устройств
WARP_API = "https://api.cloudflareclient.com/v0a2158/reg"

def generate_wireguard_keys():
    """Генерирует пару ключей X25519 (Private/Public) в формате Base64"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # WireGuard требует стандартный Base64
    priv_b64 = base64.b64encode(priv_bytes).decode('utf-8')
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    return priv_b64, pub_b64

def register_warp_device():
    """Регистрирует новое устройство в Cloudflare WARP (несколько endpoint'ов + curl fallback)"""
    priv_key, pub_key = generate_wireguard_keys()
    
    payload = {
        "key": pub_key,
        "install_id": "",
        "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "PC",
        "type": "Linux",
        "locale": "en_US"
    }
    
    # Список возможных endpoint'ов (старые и новые версии API)
    endpoints = [
        "https://api.cloudflareclient.com/v0a2158/reg",
        "https://api.cloudflareclient.com/v0a2223/reg",
        "https://api.cloudflareclient.com/v0a1928/reg",
        "https://api.devices.cloudflare.com/v0a2158/reg",  # Новый endpoint (2026.6.0+)
    ]
    
    data = json.dumps(payload).encode('utf-8')
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for url in endpoints:
        print(f"  {C.DIM}Пробую {url.split('/')[2]}...{C.RESET}", end=" ")
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "okhttp/3.12.1",
                    "CF-Client-Version": "a-6.11-2158",
                    "Accept": "application/json",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                config = result.get("config", {})
                peers = config.get("peers", [])
                if not peers:
                    print(f"{C.YELLOW}⚠ нет peer{C.RESET}")
                    continue
                
                peer = peers[0]
                endpoint = peer.get("endpoint", {})
                endpoint_host = endpoint.get("host", "engage.cloudflareclient.com")
                endpoint_port = endpoint.get("port", 2408)
                addresses = config.get("interface", {}).get("addresses", {})
                ipv4 = addresses.get("v4", "172.16.0.2")
                ipv6 = addresses.get("v6", "2606:4700:110:8a36:df92:102a:9602:fa18")
                peer_pub_key = peer.get("public_key")
                
                print(f"{C.GREEN}✅{C.RESET}")
                return {
                    "private_key": priv_key,
                    "public_key": pub_key,
                    "peer_public_key": peer_pub_key,
                    "endpoint_host": endpoint_host,
                    "endpoint_port": endpoint_port,
                    "ipv4": ipv4,
                    "ipv6": ipv6
                }
        except Exception as e:
            print(f"{C.RED}❌ ({str(e)[:40]}){C.RESET}")
            continue
    
    # Fallback: пробуем через curl (обходит проблемы с SSL в Python)
    print(f"  {C.DIM}Все endpoint'ы не ответили. Пробую через curl...{C.RESET}")
    try:
        import subprocess
        curl_cmd = [
            "curl", "-s", "-X", "POST",
            "https://api.cloudflareclient.com/v0a2158/reg",
            "-H", "Content-Type: application/json",
            "-H", "User-Agent: okhttp/3.12.1",
            "-H", "CF-Client-Version: a-6.11-2158",
            "-d", json.dumps(payload),
            "--max-time", "20",
            "--insecure"
        ]
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=25)
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            config = data.get("config", {})
            peers = config.get("peers", [])
            if peers:
                peer = peers[0]
                endpoint = peer.get("endpoint", {})
                addresses = config.get("interface", {}).get("addresses", {})
                print(f"  {C.GREEN}✅ curl сработал{C.RESET}")
                return {
                    "private_key": priv_key,
                    "public_key": pub_key,
                    "peer_public_key": peer.get("public_key"),
                    "endpoint_host": endpoint.get("host", "engage.cloudflareclient.com"),
                    "endpoint_port": endpoint.get("port", 2408),
                    "ipv4": addresses.get("v4", "172.16.0.2"),
                    "ipv6": addresses.get("v6", "2606:4700:110:8a36:df92:102a:9602:fa18")
                }
        print(f"  {C.RED}curl тоже не сработал: {result.stderr[:100]}{C.RESET}")
    except Exception as e:
        print(f"  {C.RED}Ошибка curl: {e}{C.RESET}")
    
    return None

def generate_awg_config(mode="awg2"):
    """Собирает .conf файл AmneziaWG на основе данных WARP"""
    print(f"  {C.DIM}[*] Регистрация нового устройства в Cloudflare WARP...{C.RESET}", end=" ")
    warp = register_warp_device()
    if not warp:
        print(f"{C.RED}❌{C.RESET}")
        return None
    
    print(f"{C.GREEN}✅{C.RESET}")
    
    # Параметры обфускации для разных версий AmneziaWG
    # (значения взяты из открытых генераторов, можно рандомизировать)
    if mode == "legacy":
        jc, jmin, jmax = 0, 0, 0
        s1, s2, s3, s4 = 0, 0, 0, 0
        h1, h2, h3, h4 = 1, 2, 3, 4
    elif mode == "awg31":
        # Более агрессивная обфускация для AWG 3.1
        jc, jmin, jmax = 120, 50, 1000
        s1, s2, s3, s4 = 15, 80, 20, 120
        h1, h2, h3, h4 = 1234567, 2345678, 3456789, 4567890
    else: # awg2 (по умолчанию)
        jc, jmin, jmax = 4, 50, 1000
        s1, s2, s3, s4 = 5, 10, 15, 20
        h1, h2, h3, h4 = 1, 2, 3, 4
        
    config = f"""[Interface]
PrivateKey = {warp['private_key']}
Address = {warp['ipv4']}/32, {warp['ipv6']}/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
S3 = {s3}
S4 = {s4}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}

[Peer]
PublicKey = {warp['peer_public_key']}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {warp['endpoint_host']}:{warp['endpoint_port']}
PersistentKeepalive = 25
"""
    return config

def menu_awg_gen():
    header("ГЕНЕРАЦИЯ AMNEZIAWG (Локально, Cloudflare WARP)")
    print(f"{C.DIM}Без внешних API. Прямая регистрация в Cloudflare WARP.{C.RESET}")
    print(f"{C.DIM}Каждый запуск создаёт новый конфиг с уникальными ключами.{C.RESET}\n")
    
    print(f"{C.BOLD}Выберите формат:{C.RESET}")
    print("  1) AWG 2.0 (стабильный, совместимый)")
    print("  2) AWG 3.1 (новый, с обфускацией)")
    print("  3) Legacy (WireGuard без обфускации)")
    
    ch = ask("Выбор [1]: ") or '1'
    mode_map = {'1': 'awg2', '2': 'awg31', '3': 'legacy'}
    mode = mode_map.get(ch, 'awg2')
    
    raw = ask("Сколько конфигов сгенерировать? [1]: ")
    try: count = max(1, min(int(raw) if raw else 1, 5))
    except: count = 1
    
    print(f"\n{C.BOLD}Генерирую {count} конфиг(ов) в формате {mode.upper()}...{C.RESET}")
    
    configs = []
    for i in range(count):
        print(f"  {C.DIM}[{i+1}/{count}]{C.RESET}", end=" ")
        cfg = generate_awg_config(mode=mode)
        if cfg:
            configs.append(cfg)
            print(f"{C.GREEN}✅{C.RESET}")
        else:
            print(f"{C.RED}❌{C.RESET}")
        time.sleep(1) # Небольшая пауза между регистрациями
    
    if not configs:
        print(f"\n{C.RED}Не удалось сгенерировать ни один конфиг.{C.RESET}")
        pause()
        return
        
    # Сохраняем в папку Загрузки
    download_dir = os.path.expanduser("~/storage/downloads")
    if not os.path.exists(download_dir):
        download_dir = "/sdcard/Download"
    if not os.path.exists(download_dir):
        download_dir = "."
        
    conf_path = os.path.join(download_dir, "amneziawg_configs.conf")
    with open(conf_path, 'w', encoding='utf-8') as f:
        for i, cfg in enumerate(configs):
            if i > 0:
                f.write('\n\n')
            f.write(cfg)
            
    print(f"\n{C.GREEN}✅ Конфиги AmneziaWG сохранены:{C.RESET}")
    print(f"  {C.CYAN}{conf_path}{C.RESET}")
    
    print(f"\n{C.BOLD}Как импортировать в AmneziaVPN:{C.RESET}")
    print(f"  {C.GREEN}1.{C.RESET} Открой файл {C.DIM}amneziawg_configs.conf{C.RESET}")
    print(f"  {C.GREEN}2.{C.RESET} Скопируй один блок [Interface]...[Peer]...")
    print(f"  {C.GREEN}3.{C.RESET} В Amnezia: + → Импорт из буфера обмена")
    
    pause()
