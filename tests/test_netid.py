"""MAC/serial identity checks and automatic IP relocation."""
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_dir = tempfile.TemporaryDirectory()
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + str(Path(_dir.name) / 'app.db'))
os.environ.setdefault('SESSION_SECRET', 'integration-test-secret')
os.environ.setdefault('ADMIN_PASSWORD', 'admin-password-for-tests')
os.environ.setdefault('VIEWER_PASSWORD', 'viewer-password-for-tests')

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app, engine, Printer, Reading, IpChange, CollectionEvent, CollectionState, BillingConfig
from app.netid import normalize_mac, parse_if_phys, parse_arp_table, parse_proc_arp, parse_subnets, serial_matches

OID = '1.3.6.1.2.1.43.10.2.1.4.1.1'
DOWN = {'reachable': False, 'macs': [], 'serial': None}


def dev(mac, serial=None):
    return {'reachable': True, 'macs': [mac] if mac else [], 'serial': serial}


class Parsers(unittest.TestCase):
    def test_mac_formats(self):
        for raw in ('64 EB 8C 01 02 03', '64:eb:8c:1:2:3', '64-EB-8C-01-02-03', '64eb8c010203', '64eb.8c01.0203'):
            self.assertEqual(normalize_mac(raw), '64:eb:8c:01:02:03', raw)
        for raw in ('', '00 00 00 00 00 00', 'zz:zz', '64:eb:8c:01:02'):
            self.assertIsNone(normalize_mac(raw), raw)

    def test_if_phys_walk(self):
        out = ('.1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 64 EB 8C 01 02 03 \n'
               '.1.3.6.1.2.1.2.2.1.6.2 = ""\n'
               '.1.3.6.1.2.1.2.2.1.6.3 = Hex-STRING: 00 00 00 00 00 00 \n'
               '.1.3.6.1.2.1.2.2.1.6.4 = STRING: 66:eb:8c:1:2:4\n')
        self.assertEqual(parse_if_phys(out), ['64:eb:8c:01:02:03', '66:eb:8c:01:02:04'])

    def test_router_arp_table(self):
        out = ('.1.3.6.1.2.1.4.22.1.2.7.192.168.10.84 = Hex-STRING: 64 EB 8C 01 02 03 \n'
               '.1.3.6.1.2.1.4.22.1.2.7.192.168.10.85 = Hex-STRING: 00 00 00 00 00 00 \n')
        self.assertEqual(parse_arp_table(out), {'192.168.10.84': '64:eb:8c:01:02:03'})
        proc = ('IP address       HW type     Flags       HW address            Mask     Device\n'
                '172.18.0.1       0x1         0x2         02:42:ac:12:00:01     *        eth0\n'
                '172.18.0.9       0x1         0x0         00:00:00:00:00:00     *        eth0\n')
        self.assertEqual(parse_proc_arp(proc), {'172.18.0.1': '02:42:ac:12:00:01'})

    def test_subnets_and_serial(self):
        self.assertEqual([str(n) for n in parse_subnets('192.168.10.7/24, 192.168.11.0/24')], ['192.168.10.0/24', '192.168.11.0/24'])
        with self.assertRaises(ValueError): parse_subnets('10.0.0.0/16')
        with self.assertRaises(ValueError): parse_subnets('banana')
        self.assertTrue(serial_matches('X3CF000355', 'x3cf-000355'))
        self.assertTrue(serial_matches('X3CF000355', 'SN X3CF000355'))
        self.assertFalse(serial_matches('X3CF000355', 'X3CF000569'))
        self.assertFalse(serial_matches('X3CF000355', None))


class Relocation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app); cls.client.__enter__()
        token = re.search(r'name="token" value="([^"]+)', cls.client.get('/login').text).group(1)
        r = cls.client.post('/login', data={'username': 'admin', 'password': 'admin-password-for-tests', 'token': token}, follow_redirects=True)
        cls.token = re.search(r'name="token" value="([^"]+)', r.text).group(1)

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        with Session(engine) as db:
            db.get(CollectionState, 1).last_locate_at = None
            conf = db.get(BillingConfig, 1); conf.scan_subnets = ''; conf.arp_router = ''
            db.commit()
        self.net = {}; self.counters = {}; self.hints = {}; self.sweeps = []

    def add(self, name, serial, ip, mac=None):
        with Session(engine) as db:
            p = Printer(name=name, serial=serial, model='WF-M5299', ip=ip, mac=mac, oid_bw=OID, oid_color='', snmp_version='2c')
            db.add(p); db.commit(); return p.id

    def run_patched(self, call):
        def fake_sweep(subnets, versions=('2c',), skip=()):
            self.sweeps.append(subnets)
            return {ip: fp for ip, fp in self.net.items() if fp['reachable']}
        with patch('app.main.fingerprint', side_effect=lambda ip, version='2c', **kw: self.net.get(ip, DOWN)), \
             patch('app.main.arp_hints', side_effect=lambda router=None: dict(self.hints)), \
             patch('app.main.sweep', side_effect=fake_sweep), \
             patch('app.main.snmp', side_effect=lambda ip, oid, version='2c': self.counters.get(ip)):
            return call()

    def collect(self, pid):
        r = self.run_patched(lambda: self.client.post(f'/printers/{pid}/collect', data={'token': self.token}))
        self.assertEqual(r.status_code, 200)

    def test_learns_mac_on_first_collection(self):
        pid = self.add('Aprende', 'LEARN00001', '198.51.100.10')
        self.net['198.51.100.10'] = dev('64:eb:8c:00:00:10', 'LEARN00001'); self.counters['198.51.100.10'] = 500
        self.collect(pid)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, pid).mac, '64:eb:8c:00:00:10')
            self.assertEqual(db.query(Reading).filter_by(printer_id=pid).one().counter, 500)

    def test_moves_using_router_arp(self):
        pid = self.add('Mudou', 'MOVED00001', '198.51.100.20', '64:eb:8c:00:00:20')
        self.hints = {'198.51.100.120': '64:eb:8c:00:00:20'}
        self.net['198.51.100.120'] = dev('64:eb:8c:00:00:20'); self.counters['198.51.100.120'] = 700
        self.collect(pid)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, pid).ip, '198.51.100.120')
            change = db.query(IpChange).filter_by(printer_id=pid).one()
            self.assertEqual((change.old_ip, change.new_ip), ('198.51.100.20', '198.51.100.120'))
            self.assertEqual(db.query(Reading).filter_by(printer_id=pid).one().counter, 700)
            self.assertTrue(db.query(CollectionEvent).filter_by(printer_id=pid, code='ip_changed').count())
        self.assertEqual(self.sweeps, [])  # ARP was enough
        self.assertIn('198.51.100.120', self.client.get('/printers').text)

    def test_swapped_ips_never_mix_counters(self):
        a = self.add('Troca A', 'SWAPA00001', '198.51.100.31', '64:eb:8c:00:00:31')
        b = self.add('Troca B', 'SWAPB00001', '198.51.100.32', '64:eb:8c:00:00:32')
        with Session(engine) as db: db.get(BillingConfig, 1).scan_subnets = '198.51.100.0/24'; db.commit()
        # DHCP swapped the two printers.
        self.net['198.51.100.31'] = dev('64:eb:8c:00:00:32'); self.counters['198.51.100.31'] = 2222
        self.net['198.51.100.32'] = dev('64:eb:8c:00:00:31'); self.counters['198.51.100.32'] = 1111
        self.collect(a)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, a).ip, '198.51.100.32')
            self.assertEqual(db.query(Reading).filter_by(printer_id=a).one().counter, 1111)
            self.assertEqual(db.get(Printer, b).ip, '198.51.100.31')  # B relocated in the same run
            self.assertEqual(db.query(IpChange).filter_by(printer_id=b).count(), 2)  # cleared, then moved
        self.collect(b)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, b).ip, '198.51.100.31')
            self.assertEqual(db.query(Reading).filter_by(printer_id=b).one().counter, 2222)

    def test_unknown_device_on_ip_blocks_reading(self):
        pid = self.add('Bloqueio', 'BLOCK00001', '198.51.100.40', '64:eb:8c:00:00:40')
        self.net['198.51.100.40'] = dev('aa:bb:cc:00:00:40'); self.counters['198.51.100.40'] = 9999
        self.collect(pid)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, pid).ip, '198.51.100.40')
            self.assertEqual(db.query(Reading).filter_by(printer_id=pid).count(), 0)
            self.assertTrue(db.query(CollectionEvent).filter_by(printer_id=pid, code='identity_mismatch').count())

    def test_ambiguous_candidates_change_nothing(self):
        pid = self.add('Ambígua', 'AMBIG00001', '198.51.100.50')
        with Session(engine) as db: db.get(BillingConfig, 1).scan_subnets = '198.51.100.0/24'; db.commit()
        self.net['198.51.100.150'] = dev(None, 'AMBIG00001'); self.net['198.51.100.151'] = dev(None, 'AMBIG00001')
        self.collect(pid)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, pid).ip, '198.51.100.50')
            self.assertTrue(db.query(CollectionEvent).filter_by(printer_id=pid, code='locate_ambiguous').count())

    def test_serial_format_difference_only_warns(self):
        pid = self.add('Canon', 'CANONTEST1', '198.51.100.60')
        self.net['198.51.100.60'] = dev('64:eb:8c:00:00:60', 'CANON-XYZ-0001'); self.counters['198.51.100.60'] = 42
        self.collect(pid)
        with Session(engine) as db:
            self.assertIsNone(db.get(Printer, pid).mac)
            self.assertEqual(db.query(Reading).filter_by(printer_id=pid).one().counter, 42)
            self.assertTrue(db.query(CollectionEvent).filter_by(printer_id=pid, code='serial_mismatch').count())

    def test_locate_finds_printer_without_ip_by_serial(self):
        pid = self.add('Sem IP', 'NOIP000001', '')
        with Session(engine) as db: db.get(BillingConfig, 1).scan_subnets = '198.51.100.0/24'; db.commit()
        self.net['198.51.100.70'] = dev('64:eb:8c:00:00:70', 'NOIP000001')
        r = self.run_patched(lambda: self.client.post('/printers/locate', data={'token': self.token}, follow_redirects=True))
        self.assertEqual(r.status_code, 200)
        self.assertIn('Última verificação de rede', r.text)
        with Session(engine) as db:
            p = db.get(Printer, pid)
            self.assertEqual((p.ip, p.mac), ('198.51.100.70', '64:eb:8c:00:00:70'))

    def test_settings_and_manual_mac(self):
        bad = self.client.post('/settings', data={'fixed_fee': '0', 'jump_limit': '2000', 'collection_interval_hours': '24', 'scan_subnets': '10.0.0.0/8', 'token': self.token})
        self.assertEqual(bad.status_code, 400)
        ok = self.client.post('/settings', data={'fixed_fee': '0', 'jump_limit': '2000', 'collection_interval_hours': '24', 'scan_subnets': '198.51.100.9/24', 'arp_router': '198.51.100.1', 'token': self.token})
        self.assertEqual(ok.status_code, 200)
        with Session(engine) as db: self.assertEqual(db.get(BillingConfig, 1).scan_subnets, '198.51.100.0/24')
        pid = self.add('Manual', 'MANUAL0001', '198.51.100.80')
        r = self.client.post(f'/printers/{pid}', data={'name': 'Manual', 'serial': 'MANUAL0001', 'ip': '198.51.100.81', 'mac': '64-EB-8C-00-00-80', 'token': self.token})
        self.assertEqual(r.status_code, 200)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer, pid).mac, '64:eb:8c:00:00:80')
            self.assertEqual(db.query(IpChange).filter_by(printer_id=pid).one().evidence, 'edição manual por admin')
        dup = self.add('Duplicada', 'MANUAL0002', '198.51.100.82')
        r = self.client.post(f'/printers/{dup}', data={'name': 'Duplicada', 'mac': '64:eb:8c:00:00:80', 'token': self.token})
        self.assertEqual(r.status_code, 400)


if __name__ == '__main__':
    unittest.main()
