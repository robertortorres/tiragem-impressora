"""Printer network identity: MAC/serial fingerprints and IP relocation.

Printers fed by DHCP may change IP. Recording counters by IP alone can then
attribute another printer's counter to the wrong record. This module gathers
evidence of *who* answers at an address and where a known device went:

* fingerprint(ip): MAC addresses (IF-MIB ifPhysAddress) and serial number
  (Printer MIB prtGeneralSerialNumber) reported by the device over SNMP.
  Works across routers, unlike ARP.
* arp_hints(): IP->MAC pairs from a router's ARP table via SNMP
  (ipNetToMediaPhysAddress, e.g. a MikroTik gateway) and from the local
  /proc/net/arp. A hint is only a hint: the new address is always confirmed
  with fingerprint() before the inventory changes.
* sweep(subnets): fingerprints every host of the configured subnets in
  parallel, used when hints are not enough.
"""
import ipaddress
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

IF_PHYS_ADDRESS = '1.3.6.1.2.1.2.2.1.6'
ARP_TABLE = '1.3.6.1.2.1.4.22.1.2'
SERIAL_OID = '1.3.6.1.2.1.43.5.1.1.17.1'
MAX_SWEEP_HOSTS = 4096
SWEEP_WORKERS = int(os.environ.get('SWEEP_WORKERS', '64'))
_HEX_MAC = re.compile(r'(?:Hex-STRING|STRING):\s*"?((?:[0-9A-Fa-f]{1,2}[ :-]?){6})"?\s*$')
MAC_RE = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')


def snmp_args(version, command, community=None):
    if version == '3':
        username = os.environ.get('SNMPV3_USER'); auth = os.environ.get('SNMPV3_AUTH_PASSWORD'); privacy = os.environ.get('SNMPV3_PRIV_PASSWORD')
        if not all((username, auth, privacy)): return None
        return [command, '-v', '3', '-l', 'authPriv', '-u', username, '-a', 'SHA', '-A', auth, '-x', 'AES', '-X', privacy]
    if version not in ('1', '2c'): return None
    return [command, '-v', version, '-c', community or os.environ.get('SNMP_COMMUNITY', 'public')]


def normalize_mac(value):
    """Return aa:bb:cc:dd:ee:ff, or None for empty, malformed or all-zero values."""
    if not value: return None
    parts = re.split(r'[\s:.-]+', str(value).strip())
    if len(parts) == 1 and len(parts[0]) == 12: parts = re.findall('..', parts[0])
    if len(parts) == 3 and all(len(p) == 4 for p in parts): parts = re.findall('..', ''.join(parts))
    if len(parts) != 6 or not all(re.fullmatch(r'[0-9A-Fa-f]{1,2}', p) for p in parts): return None
    mac = ':'.join(p.zfill(2).lower() for p in parts)
    if mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'): return None
    return mac


def normalize_serial(value):
    return re.sub(r'[^0-9A-Z]', '', str(value or '').upper()) or None


def serial_matches(expected, reported):
    """Tolerate vendor padding/prefixes; never match empty values."""
    a, b = normalize_serial(expected), normalize_serial(reported)
    if not a or not b or min(len(a), len(b)) < 6: return False
    return a == b or a in b or b in a


def _run(args, timeout):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def parse_if_phys(output):
    """MACs in ifIndex order from `snmpwalk -On -Ox` output of ifPhysAddress."""
    macs = []
    for line in output.splitlines():
        m = _HEX_MAC.search(line)
        mac = normalize_mac(m.group(1)) if m else None
        if mac and mac not in macs: macs.append(mac)
    return macs


def parse_arp_table(output):
    """{ip: mac} from `snmpwalk -On -Ox` of ipNetToMediaPhysAddress."""
    result = {}
    prefix = re.compile(r'^\.?' + re.escape(ARP_TABLE) + r'\.\d+\.(\d+\.\d+\.\d+\.\d+)\s*=')
    for line in output.splitlines():
        p = prefix.match(line.strip()); m = _HEX_MAC.search(line)
        mac = normalize_mac(m.group(1)) if m else None
        if p and mac: result[p.group(1)] = mac
    return result


def parse_proc_arp(text):
    result = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4 and cols[2] == '0x2':
            mac = normalize_mac(cols[3])
            if mac: result[cols[0]] = mac
    return result


def fingerprint(ip, version='2c', timeout=2, retries=0):
    """{'reachable': bool, 'macs': [...], 'serial': str|None} for one address."""
    empty = {'reachable': False, 'macs': [], 'serial': None}
    walk = snmp_args(version, 'snmpwalk'); get = snmp_args(version, 'snmpget')
    if not ip or walk is None: return empty
    p = _run(walk + ['-On', '-Ox', '-t', str(timeout), '-r', str(retries), ip, IF_PHYS_ADDRESS], timeout * (retries + 1) + 4)
    if p is None or p.returncode != 0: return empty
    macs = parse_if_phys(p.stdout)
    s = _run(get + ['-Oqv', '-t', str(timeout), '-r', str(retries), ip, SERIAL_OID], timeout * (retries + 1) + 3)
    serial = None
    if s is not None and s.returncode == 0:
        value = s.stdout.strip().strip('"')
        if value and 'No Such' not in value and 'no such' not in value.lower(): serial = value
    return {'reachable': True, 'macs': macs, 'serial': serial}


def arp_hints(router=None):
    """IP->MAC hints. Never authoritative: confirm with fingerprint()."""
    hints = {}
    try:
        with open('/proc/net/arp') as handle: hints.update(parse_proc_arp(handle.read()))
    except OSError:
        pass
    if router:
        args = snmp_args('2c', 'snmpwalk', os.environ.get('ARP_SNMP_COMMUNITY') or None)
        p = _run(args + ['-On', '-Ox', '-t', '3', '-r', '1', router, ARP_TABLE], 30)
        if p is not None and p.returncode == 0: hints.update(parse_arp_table(p.stdout))
    return hints


def parse_subnets(value):
    """Validate a comma/space separated CIDR list. Raises ValueError."""
    networks = []
    for item in re.split(r'[\s,;]+', value or ''):
        if not item: continue
        try: net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc: raise ValueError(f'Rede inválida: {item}') from exc
        if net.version != 4: raise ValueError(f'Somente IPv4 na varredura: {item}')
        networks.append(net)
    if sum(max(n.num_addresses - 2, 1) for n in networks) > MAX_SWEEP_HOSTS:
        raise ValueError(f'As redes somam mais de {MAX_SWEEP_HOSTS} endereços')
    return networks


def sweep(subnets, versions=('2c',), skip=()):
    """Fingerprint every host in subnets. Returns {ip: fingerprint} of responders."""
    hosts = []
    for net in parse_subnets(subnets):
        hosts.extend(str(h) for h in (net.hosts() if net.num_addresses > 2 else net))
    hosts = [h for h in dict.fromkeys(hosts) if h not in set(skip)]
    found = {}
    for version in dict.fromkeys(versions):
        pending = [h for h in hosts if h not in found]
        if not pending: break
        with ThreadPoolExecutor(max_workers=max(1, SWEEP_WORKERS)) as pool:
            for ip, fp in zip(pending, pool.map(lambda h: fingerprint(h, version, timeout=1, retries=1), pending)):
                if fp['reachable']: found[ip] = fp
    return found
