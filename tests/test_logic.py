import unittest
from datetime import date
from decimal import Decimal
from app.logic import usage, month_bounds, money, parse_librenms_csv

class Calculations(unittest.TestCase):
    def test_reset(self):
        self.assertEqual(usage(995,8),(None,'reset'))
        self.assertEqual(usage(995,8,1000),(13,'rollover'))
        self.assertEqual(usage(100,125),(25,'ok'))
    def test_month(self):self.assertEqual(month_bounds('2026-12'),(date(2026,12,1),date(2027,1,1)))
    def test_money(self):self.assertEqual(money('1.530,64'),Decimal('1530.64'))
    def test_csv(self):
        rows=parse_librenms_csv(b'serial;data;pb;cor\nABC;10/09/2026;150;20\n')
        self.assertEqual(rows,[('ABC',date(2026,9,10),'bw',150),('ABC',date(2026,9,10),'color',20)])
        rows=parse_librenms_csv(b'hostname,timestamp,kind,counter\nprinter,2026-09-10 09:00:00,mono,250\n')
        self.assertEqual(rows[0][2:],('bw',250))
    def test_bad_counter(self):
        with self.assertRaises(ValueError):parse_librenms_csv(b'serial,date,bw\nABC,2026-09-10,-1\n')
