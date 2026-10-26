import socket, ssl, time, struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import C, HTTP_PORTS, SSH_PORTS, KNOWN_SERVICES
from .utils import progress_line, progress_end, jitter

def grab_banner(ip, port, timeout=1.5):
    info = {'banner':'','service':KNOWN_SERVICES.get(port,''),'risk':None,'extra':[], 'silent': False}
    
    # 1. HTTP/HTTPS
    if port in HTTP_PORTS:
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip,port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n")
            d = s.recv(1024).decode('utf-8','ignore'); s.close()
            if d:
                info['service'] = 'HTTP'
                parts = [l.strip() for l in d.split('\r\n')
                         if l.lower().startswith(('server:','x-powered-by:'))]
                info['banner'] = ' | '.join(parts) if parts else d.split('\r\n')[0][:80]
                return info
            else:
                info['silent'] = True
                return info
        except socket.timeout:
            info['silent'] = True; return info
        except: pass

    # 2. HTTPS
    if port in (443,8443):
        try:
            ctx = ssl._create_unverified_context()
            s = socket.socket(); s.settimeout(timeout)
            ss = ctx.wrap_socket(s, server_hostname=ip); ss.connect((ip,port))
            info['service'] = 'HTTPS'
            info['banner'] = f"TLS {ss.version()} · {ss.cipher()[0]}"
            ss.close(); return info
        except socket.timeout:
            info['silent'] = True; return info
        except: pass

    # 3. SSH
    if port in SSH_PORTS:
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip,port))
            d = s.recv(256).decode('utf-8','ignore').strip(); s.close()
            if d:
                info['service'] = 'SSH'; info['banner'] = d
                if d.startswith('SSH-2.0-OpenSSH_'):
                    import re
                    m = re.search(r'OpenSSH_(\d+)\.(\d+)', d)
                    if m and int(m.group(1)) < 7:
                        info['risk'] = f'Старый OpenSSH {m.group(1)}.{m.group(2)}'
                return info
            else:
                info['silent'] = True; return info
        except socket.timeout:
            info['silent'] = True; return info
        except: pass

    # 4. FTP
    if port == 21:
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip,port))
            d = s.recv(256).decode('utf-8','ignore').strip()
            if d:
                info['service'] = 'FTP'; info['banner'] = d
                s.sendall(b'USER anonymous\r\n'); s.settimeout(1)
                r1 = s.recv(256).decode('utf-8','ignore')
                if r1.startswith('331'):
                    s.sendall(b'PASS anonymous@\r\n')
                    r2 = s.recv(256).decode('utf-8','ignore')
                    if r2.startswith('230'):
                        info['banner'] += ' | ⚠ АНОНИМ'
                        info['risk'] = 'FTP аноним'
                s.close(); return info
            else:
                info['silent'] = True; return info
        except socket.timeout:
            info['silent'] = True; return info
        except: pass

    # 5. Redis
    if port == 6379:
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip,port))
            s.sendall(b'PING\r\n'); d = s.recv(128).decode('utf-8','ignore').strip(); s.close()
            if 'PONG' in d:
                info['service'] = 'Redis'; info['banner'] = f'{d} (нет пароля!)'
                info['risk'] = 'Redis без пароля'
                return info
            else:
                info['silent'] = True; return info
        except socket.timeout:
            info['silent'] = True; return info
        except: pass

    # 6. VNC
    if port in (5900,5901):
        try:
            s = socket.socket(); s.settimeout(timeout); s.connect((ip,port))
            d = s.recv(12); s.close()
            if d.startswith(b'RFB'):
                info['service'] = 'VNC'; info['banner'] = f'RFB {d[4:].decode("utf-8","ignore")}'
                # проверка на отсутствие аутентификации
                try:
                    s2 = socket.socket(); s2.settimeout(1.5); s2.connect((ip,port))
                    s2.recv(12); s2.sendall(b'\x01\x00')
                    r = s2.recv(4); s2.close()
                    if len(r) >= 4 and r[3] == 1:
                        info['risk'] = 'VNC без пароля!'
                except: pass
                return info
            else:
                info['silent'] = True; return info
        except socket.timeout:
            info['silent'] = True; return info
        except: pass

    # 7. Fallback (любой другой порт)
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip,port))
        # Отправляем пустой запрос (только перевод строки), чтобы спровоцировать ответ
        try:
            s.sendall(b"\r\n")
            s.settimeout(0.8)
            d = s.recv(128).decode('utf-8','ignore').strip()
            if d:
                info['banner'] = d[:80]
            else:
                info['silent'] = True
        except socket.timeout:
            info['silent'] = True
        s.close()
    except: pass

    return info

def check_tcp(ip, port, timeout=1.5, deep=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
    try:
        if s.connect_ex((ip,port)) == 0:
            s.close()
            # Если глубокая проверка включена, или порт не в списке известных (чтобы не спамить),
            # вызываем grab_banner для проверки на "молчание"
            if deep or port not in KNOWN_SERVICES:
                info = grab_banner(ip, port, timeout*1.5)
                return (port, True, info)
            else:
                return (port, True, {'banner':'','service':KNOWN_SERVICES.get(port,''),'risk':None,'extra':[], 'silent': False})
    except: pass
    finally:
        try: s.close()
        except: pass
    return (port, False, None)

def check_udp(ip, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(b'\x00', (ip, port))
        try:
            d,_ = s.recvfrom(64); return (port, True, f'ответ {len(d)}б')
        except socket.timeout: return (port, None, 'нет ответа')
        except ConnectionRefusedError: return (port, False, 'ICMP unreachable')
    except Exception as e: return (port, False, str(e)[:30])
    finally: s.close()

def run_scan(ip, ports, threads, timeout=1.5, do_udp=False, deep=False, auto_crawl=False, jit=False):
    from .reports import save_report_txt
    from .http_utils import crawl_site
    
    open_tcp = []; open_udp = []; risks = []; http_ports = []; silent_ports = []
    t0 = time.time(); done = 0; total = len(ports)
    print(f"\n{C.BOLD}[TCP]{C.RESET} {total} портов · {threads} потоков · "
          f"{'глубоко' if deep else 'быстро'}{' + jitter' if jit else ''}\n")
          
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check_tcp, ip, p, timeout, deep): p for p in ports}
        for fut in as_completed(futs):
            done += 1
            if jit and done % 7 == 0: jitter(0.01, 0.05)
            port, is_open, info = fut.result()
            
            if is_open:
                progress_end()
                svc = info.get('service') or KNOWN_SERVICES.get(port,'?')
                
                if info.get('silent'):
                    # Порт открыт, но молчит. Показываем только первые 10, чтобы не засорять экран
                    silent_ports.append(port)
                    if len(silent_ports) <= 10:
                        print(f"  {C.YELLOW}✓{C.RESET} {C.BOLD}{port:<6}{C.RESET} {C.YELLOW}{svc:<22} [Open · Silent/Proxy?]{C.RESET}")
                    elif len(silent_ports) == 11:
                        print(f"  {C.DIM}... (ещё много молчащих портов, скрываю вывод){C.RESET}")
                else:
                    print(f"  {C.GREEN}✓{C.RESET} {C.BOLD}{port:<6}{C.RESET} {C.CYAN}{svc:<22}{C.RESET}")
                    if info.get('banner'):
                        col = C.RED if info.get('risk') else C.DIM
                        print(f"      {col}{info['banner'][:100]}{C.RESET}")
                    if info.get('risk'):
                        risks.append((port, info['risk']))
                        print(f"      {C.RED}⚠ {info['risk']}{C.RESET}")
                
                open_tcp.append((port, svc))
                if port in HTTP_PORTS or port in (80,443,8443): http_ports.append(port)
            else:
                progress_line(f"[{done}/{total}] {done*100//total}% · открыто {len(open_tcp)}")
    progress_end()
    print(f"\n{C.BOLD}{C.GREEN}TCP готово за {time.time()-t0:.1f}с. Открыто: {len(open_tcp)}{C.RESET}")
    
    if silent_ports:
        print(f"{C.YELLOW}⚠ Молчащих портов (возможно, прокси/фаервол): {len(silent_ports)}{C.RESET}")
        print(f"{C.DIM}  (Брутфорс на таких портах бесполезен — сервис не отвечает){C.RESET}")

    if do_udp:
        print(f"\n{C.BOLD}[UDP]{C.RESET} {total} портов...")
        answered = []; silent = []; closed = 0; done = 0
        with ThreadPoolExecutor(max_workers=min(threads,100)) as ex:
            futs = {ex.submit(check_udp, ip, p, timeout): p for p in ports}
            for fut in as_completed(futs):
                done += 1
                port, st, note = fut.result()
                if st is True:
                    progress_end()
                    print(f"  {C.GREEN}✓{C.RESET} UDP {port:<6} {C.DIM}{note}{C.RESET}")
                    answered.append(port); open_udp.append(port)
                elif st is False: closed += 1
                else: silent.append(port)
                progress_line(f"[{done}/{total}] · ответили {len(answered)} · молчат {len(silent)}")
        progress_end()
        print(f"\n{C.GREEN}UDP: ответили {len(answered)}, закрыто {closed}{C.RESET}")

    if risks:
        print(f"\n{C.RED}{C.BOLD}⚠️  УЯЗВИМОСТИ:{C.RESET}")
        for port, r in risks: print(f"  {C.RED}• {port}: {r}{C.RESET}")

    if http_ports:
        print(f"\n{C.BOLD}{C.CYAN}HTTP-порты: {http_ports}{C.RESET}")
        if auto_crawl:
            for p in http_ports:
                try: crawl_site(ip, p, https=p in (443,8443), timeout=timeout+2)
                except Exception as e: print(f"  {C.RED}Ошибка: {e}{C.RESET}")

    save_report_txt(ip, open_tcp, open_udp, risks, http_ports)
