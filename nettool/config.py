import os
HOME = os.path.expanduser("~")
PREFIX = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
TMPDIR = os.environ.get("TMPDIR", os.path.join(PREFIX, "tmp"))
REPORTS_DIR = os.path.join(HOME, "nettool_reports")
WHITELIST_FILE = os.path.join(HOME, ".nettool_whitelist.json")
BASELINE_FILE = os.path.join(HOME, ".nettool_baseline.json")
LOG_FILE = os.path.join(HOME, ".nettool.log")
FOUND_CREDS = os.path.join(HOME, "found_creds.txt")
os.makedirs(TMPDIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

class C:
    RESET='\033[0m'; RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    BLUE='\033[94m'; MAGENTA='\033[95m'; CYAN='\033[96m'
    BOLD='\033[1m'; DIM='\033[2m'; CLR='\033[2K\r'

COMMON_PORTS = [21,22,23,25,53,80,110,143,161,389,443,445,465,587,636,993,995,
    1080,1194,1433,1521,1723,1900,2049,2375,3000,3306,3389,5000,5060,5432,
    5900,6379,8000,8001,8002,8022,8080,8081,8082,8083,8443,8888,9000,9090,
    9119,9200,11211,19132,25565,27017,49152,49153,49154,50000]

HTTP_PORTS = {80,443,3000,5000,8000,8001,8002,8080,8081,8082,8083,8443,8888,9000,9090,9119,9200}
SSH_PORTS = [22,2222,8022]

WEB_SCAN_PORTS = [80,443,81,82,88,90,300,3000,4000,4200,5000,5060,5173,5432,
    5500,5601,7000,7001,7070,7080,7171,7474,7547,7548,7777,7860,7878,8000,
    8001,8002,8008,8010,8080,8081,8082,8083,8088,8090,8096,8111,8123,8161,
    8180,8200,8280,8282,8291,8443,8500,8787,8800,8834,8880,8888,8899,8983,
    9000,9001,9043,9090,9091,9100,9200,9418,9443,9999,10000,10250,11211]

KNOWN_SERVICES = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
    110:'POP3',123:'NTP',135:'MSRPC',137:'NetBIOS-NS',138:'NetBIOS-DGM',139:'NetBIOS-SSN',
    143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',500:'IKE',
    514:'Syslog',554:'RTSP',587:'SMTP-sub',636:'LDAPS',993:'IMAPS',995:'POP3S',
    1080:'SOCKS',1194:'OpenVPN',1433:'MSSQL',1521:'Oracle',1723:'PPTP',1900:'SSDP',
    2049:'NFS',2375:'Docker API',3000:'Node/Dev',3306:'MySQL',3389:'RDP',
    5000:'UPnP/Flask',5060:'SIP',5432:'PostgreSQL',5555:'ADB',5900:'VNC',5984:'CouchDB',
    6379:'Redis',8000:'HTTP-alt',8022:'SSH-Termux',8080:'HTTP-alt',8081:'HTTP-alt',
    8443:'HTTPS-alt',8888:'HTTP-alt',9000:'PHP-FPM',9090:'HTTP-alt',9200:'Elasticsearch',
    11211:'Memcached',19132:'MC Bedrock',25565:'MC Java',27017:'MongoDB',
    49152:'UPnP',49153:'UPnP',50000:'SAP'}

ROUTER_USERNAMES = ['admin','root','user','guest','support','administrator','cisco','ubnt',
    'pi','ubuntu','test','mercusys','mercury','tplink','dlink','netgear','asus','linksys',
    'zyxel','huawei','xiaomi','tenda','totolink','mikrotik','ubiquiti','openwrt',
    'Admin','ROOT','admin1','operator','supervisor','manager','tech','installer','service']

ROUTER_PASSWORDS_BASE = ['admin','password','1234','12345','123456','root','toor','pass',
    'qwerty','letmein','1111','0000','8888','cisco','ubnt','support','guest','mercusys',
    'tplink','dlink','netgear','asus','linksys','zyxel','huawei','xiaomi','tenda',
    'openwrt','changeme','default','secret','master','access','login','passw0rd','admin123']

SNMP_COMMUNITIES = ['public','private','community','cisco','admin','default','snmp','test','monitor']

CRAWL_PATHS = ['/robots.txt','/sitemap.xml','/admin','/admin/','/login','/dashboard',
    '/wp-admin/','/wp-login.php','/.git/HEAD','/.git/config','/.env','/.htaccess',
    '/phpinfo.php','/info.php','/config.php','/server-status','/.DS_Store','/api',
    '/api/v1/','/swagger-ui','/graphql','/status','/health','/version',
    '/backup.zip','/db.sql','/.svn/entries','/web.config','/crossdomain.xml',
    '/actuator','/actuator/env','/console','/manager/html','/jmx-console']

PANELS = {'/jenkins':'Jenkins','/grafana':'Grafana','/kibana':'Kibana',
    '/phpmyadmin':'phpMyAdmin','/portainer':'Portainer','/prometheus':'Prometheus',
    '/minio':'MinIO','/rabbitmq':'RabbitMQ','/jupyter':'Jupyter','/solr':'Solr',
    '/zabbix':'Zabbix','/nagios':'Nagios','/cacti':'Cacti','/rutorrent':'ruTorrent',
    '/transmission':'Transmission','/sonarr':'Sonarr','/radarr':'Radarr','/plex':'Plex',
    '/glpi':'GLPI','/adminer':'Adminer','/webmin':'Webmin','/cockpit':'Cockpit',
    '/unifi':'UniFi','/airflow':'Airflow','/nextcloud':'Nextcloud','/owncloud':'ownCloud'}

OUI_DB = {
    '00:1A:2B':'Apple','00:1B:63':'Apple','00:23:DF':'Apple','3C:07:54':'Apple',
    'B8:27:EB':'Raspberry Pi','DC:A6:32':'Raspberry Pi','E4:5F:01':'Raspberry Pi',
    '00:0C:29':'VMware','08:00:27':'VirtualBox','00:15:5D':'Hyper-V','00:50:56':'VMware',
    'F4:8E:38':'Dell','18:66:DA':'Dell','00:1B:21':'Intel','34:97:F6':'ASUS',
    'F8:32:E4':'ASUS','00:1F:3A':'Samsung','28:39:5E':'Samsung','B0:DF:3A':'Samsung',
    '00:1E:10':'TP-LINK','50:C7:BF':'TP-LINK','A4:2B:B0':'TP-LINK','C0:25:E9':'TP-LINK',
    'F4:F2:6D':'TP-LINK','00:1A:79':'Cisco','00:24:97':'Cisco','00:11:32':'Synology',
    '00:1B:2F':'Netgear','20:4E:7F':'Netgear','2C:30:33':'Netgear','00:17:88':'Philips',
    '00:04:4B':'NVIDIA','00:1B:78':'Sony','30:F9:ED':'Sony','00:13:A9':'Sony',
    '20:47:DA':'Sony','B4:2E:99':'Gigabyte','00:0D:93':'Apple','5C:F9:38':'Apple',
    '00:1C:B3':'Apple','00:25:00':'Apple','F0:18:98':'Apple','00:23:12':'Apple',
    '84:38:38':'Apple','A4:83:E7':'Apple','00:88:65':'Apple','A8:20:66':'Apple',
    '00:1A:11':'Google','3C:5A:B4':'Google','F4:F5:E8':'Google','54:60:09':'Google',
    '94:EB:2C':'Google','D8:6C:63':'Google','F0:EF:86':'Google',
    '00:1D:D8':'Microsoft','28:18:78':'Microsoft','60:45:BD':'Microsoft',
    '7C:1E:52':'Microsoft','C8:3F:26':'Microsoft','DC:B4:C4':'Microsoft',
}
