import socket, struct, time
from .config import C
from .utils import header, pause, beep

def check_mqtt(ip, port=1883, timeout=4):
    print(f"  {C.DIM}[MQTT] Анонимный доступ...{C.RESET}", end=" ")
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        # MQTT CONNECT (простой, без логина/пароля)
        # fixed header: 0x10, remaining length
        # protocol name "MQTT", level 4, flags 0x02 (clean session), keepalive 60
        # client id "nettool"
        client_id = b'nettool'
        var_header = b'\x00\x04MQTT\x04\x02\x00\x3c'
        payload = struct.pack('!H', len(client_id)) + client_id
        rem_len = len(var_header) + len(payload)
        # encode remaining length (variable byte)
        if rem_len < 128: rl = bytes([rem_len])
        elif rem_len < 16384: rl = bytes([0x80 | (rem_len & 0x7f), rem_len >> 7])
        else: rl = b'\x00'
        pkt = b'\x10' + rl + var_header + payload
        s.sendall(pkt)
        resp = s.recv(256); s.close()
        if len(resp) >= 4 and resp[0] == 0x20:  # CONNACK
            rc = resp[3]
            if rc == 0:
                print(f"{C.GREEN}✅ АНОНИМНЫЙ ДОСТУП РАЗРЕШЁН{C.RESET}"); beep()
                return f"MQTT (порт {port}) — анонимный доступ (CONNACK=0)"
            else:
                print(f"{C.YELLOW}⚠ CONNACK код {rc}{C.RESET}")
                return f"MQTT (порт {port}) — CONNACK={rc} (не аноним)"
        print(f"{C.RED}❌{C.RESET}")
    except Exception as e:
        print(f"{C.RED}❌ {str(e)[:40]}{C.RESET}")
    return None

def check_coap(ip, port=5683, timeout=4):
    print(f"  {C.DIM}[CoAP] Ответ на /.well-known/core...{C.RESET}", end=" ")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        # CoAP GET /​.well-known/core (простой запрос)
        # Ver=1, Type=0 (CON), TKL=0, Code=0.01 (GET), Message ID=0x1234
        # Options: Uri-Path (11) ".well-known", (11) "core"
        msg = (b'\x40\x01\x12\x34' +
               b'\xb9.well-known' +
               b'\x04core')
        s.sendto(msg, (ip, port))
        try:
            data, _ = s.recvfrom(2048)
            s.close()
            if data and (data[0] >> 6) == 1:  # CoAP версия 1
                print(f"{C.GREEN}✅ CoAP ОТВЕЧАЕТ{C.RESET}"); beep()
                # грубая оценка amplification: размер ответа / размер запроса
                amp = len(data) / len(msg) if msg else 0
                if amp > 5:
                    print(f"      {C.YELLOW}⚠ Amplification factor ≈ {amp:.1f}x{C.RESET}")
                return f"CoAP (порт {port}) — отвечает (amp ≈ {amp:.1f}x)"
        except socket.timeout: pass
        s.close()
    except Exception as e:
        print(f"{C.RED}❌ {str(e)[:40]}{C.RESET}")
    return None

def scan_iot(ip):
    header(f"IoT-ПРОТОКОЛЫ ДЛЯ {ip}")
    found = []
    for fn in (check_mqtt, check_coap):
        try:
            r = fn(ip)
            if r: found.append(r)
        except Exception as e:
            print(f"  {C.RED}{fn.__name__}: {e}{C.RESET}")
    print(f"\n{C.BOLD}{C.CYAN}{'═'*62}{C.RESET}")
    if found:
        print(f"{C.RED}⚠️  НАЙДЕНО: {len(found)}{C.RESET}")
        for f in found: print(f"  {C.GREEN}•{C.RESET} {f}")
    else:
        print(f"{C.GREEN}✓ IoT-протоколы не обнаружены (или защищены){C.RESET}")
    pause()
