"""End-to-end checks using a disposable SQLite database and the supplied PDF."""
import os
import re
import tempfile
import unittest
import io
from datetime import date
from pathlib import Path
from unittest.mock import patch

import pdfplumber
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

_dir=tempfile.TemporaryDirectory()
os.environ['DATABASE_URL']='sqlite:///'+str(Path(_dir.name)/'app.db')
os.environ['SESSION_SECRET']='integration-test-secret'
os.environ['ADMIN_PASSWORD']='admin-password-for-tests'
os.environ['VIEWER_PASSWORD']='viewer-password-for-tests'
from app.main import app,engine,Printer,Reading,PollSample,BillingConfig,DiscoveryRun,discover_oid,snmp_args

class Workflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.client=TestClient(app);cls.client.__enter__()
    @classmethod
    def tearDownClass(cls):cls.client.__exit__(None,None,None);_dir.cleanup()
    def login(self,name,password):
        token=re.search(r'name="token" value="([^"]+)',self.client.get('/login').text).group(1)
        response=self.client.post('/login',data={'username':name,'password':password,'token':token},follow_redirects=True)
        self.assertEqual(response.status_code,200)
        return re.search(r'name="token" value="([^"]+)',response.text).group(1)
    def test_create_delete_and_preserve_history(self):
        token=self.login('admin','admin-password-for-tests')
        response=self.client.post('/printers',data={'name':'Teste','serial':'TEST-SERIAL','rollover':'','token':token})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:pid=db.query(Printer).filter_by(serial='TEST-SERIAL').one().id
        response=self.client.post(f'/printers/{pid}',data={
            'name':'Teste atualizado','serial':'TEST-SERIAL','ip':'192.0.2.1',
            'rollover':'','token':token},follow_redirects=True)
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:
            printer=db.get(Printer,pid)
            self.assertEqual(printer.name,'Teste atualizado')
            self.assertIsNone(printer.rollover)
        self.client.post('/readings',data={'printer_id':pid,'day':'2026-09-10','kind':'bw','counter':'50','token':token})
        response=self.client.post(f'/printers/{pid}/delete',data={'token':token})
        self.assertEqual(response.status_code,409)
        self.client.post(f'/printers/{pid}/status',data={'active':'0','token':token})
        with Session(engine) as db:self.assertEqual(db.get(Printer,pid).active,0)
    def test_import_and_invoice(self):
        token=self.login('admin','admin-password-for-tests')
        csv=b'serial,date,bw\nX3CF000355,2026-08-10,3046\nX3CF000355,2026-09-10,3665\n'
        response=self.client.post('/import/librenms',data={'token':token},files={'file':('history.csv',csv,'text/csv')})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:self.assertEqual(db.query(Reading).filter_by(source='librenms').count(),2)
        wrong=b'serial,date,bw\nX3CF000355,2026-08-10,9999\n'
        response=self.client.post('/import/librenms',data={'token':token},files={'file':('wrong.csv',wrong,'text/csv')})
        self.assertEqual(response.status_code,409)
        pdf=Path(__file__).resolve().parents[2]/'upload'/'Demonstrativo de tiragem executada - 9.2026.pdf'
        if pdf.exists():
            response=self.client.post('/invoices',data={'token':token},files={'file':('invoice.pdf',pdf.read_bytes(),'application/pdf')})
            self.assertEqual(response.status_code,200)
            self.assertIn('Conciliação financeira',response.text)
    def test_viewer_cannot_mutate(self):
        token=self.login('consulta','viewer-password-for-tests')
        listing=self.client.get('/printers')
        self.assertEqual(listing.status_code,200)
        self.assertIn('Contador P&B',listing.text)
        self.assertIn('Boas Vindas',listing.text)
        for action in ('Cadastrar impressora','Capturar todas agora','Buscar OIDs de todas','Editar','Desativar','Excluir','Inserir leitura de referência','Configurações e auditoria'):
            self.assertNotIn(action,listing.text)
        self.assertEqual(self.client.get('/printers/new').status_code,403)
        self.assertEqual(self.client.get('/printers/1/edit').status_code,403)
        self.assertEqual(self.client.post('/printers',data={'name':'Bloqueada','token':token}).status_code,403)
        self.assertEqual(self.client.post('/collect',data={'token':token}).status_code,403)
        self.assertEqual(self.client.get('/').status_code,200)
    def test_report_all_printers_with_empty_filter(self):
        self.login('admin','admin-password-for-tests')
        filters={'start':'2026-09-28','end':'2026-09-28','printer_id':'','group':''}
        response=self.client.get('/',params=filters)
        self.assertEqual(response.status_code,200)
        self.assertIn('Relatório por período',response.text)
        export=self.client.get('/export.csv',params=filters)
        self.assertEqual(export.status_code,200)
        self.assertIn('Impressora',export.text)
        self.assertEqual(self.client.get('/',params={**filters,'printer_id':'abc'}).status_code,400)
    def test_pdf_report_uses_period_and_printer_filters(self):
        self.login('consulta','viewer-password-for-tests')
        with Session(engine) as db:
            printer=db.query(Printer).filter_by(name='Boas Vindas').one()
            printer_id=printer.id
            if not db.query(Reading).filter_by(printer_id=printer_id,day=date(2026,9,25),kind='bw').first():
                db.add_all([Reading(printer_id=printer_id,day=date(2026,9,25),kind='bw',counter=100,source='manual'),
                            Reading(printer_id=printer_id,day=date(2026,9,26),kind='bw',counter=109,source='manual')])
                db.commit()
        params={'start':'2026-09-26','end':'2026-09-26','printer_id':str(printer_id)}
        response=self.client.get('/export.pdf',params=params)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.headers['content-type'],'application/pdf')
        self.assertTrue(response.content.startswith(b'%PDF-'))
        with pdfplumber.open(io.BytesIO(response.content)) as document:
            content='\n'.join(page.extract_text() for page in document.pages)
        self.assertIn('Boas Vindas',content)
        self.assertIn('9 páginas',content)
        self.assertNotIn('Faturamento',content)
        self.assertEqual(self.client.get('/export.pdf',params={**params,'start':'2026-09-27'}).status_code,400)
    def test_snmp_v1_can_be_selected_and_used(self):
        token=self.login('admin','admin-password-for-tests')
        self.assertEqual(snmp_args('1','snmpget')[:3],['snmpget','-v','1'])
        with patch('app.main.marker_values',return_value={}):
            response=self.client.post('/printers',data={'name':'Canon teste','serial':'CANON-V1-TEST',
                'ip':'192.0.2.80','model':'iR1643i II','snmp_version':'1','token':token})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:self.assertEqual(db.query(Printer).filter_by(serial='CANON-V1-TEST').one().snmp_version,'1')
        self.assertIn('value="1" selected',response.text)
    def test_discovery_classifies_only_verified_monochrome(self):
        mono=Printer(name='Mono',model='WF-M5799',ip='192.0.2.10',snmp_version='2c',oid_bw='',oid_color='')
        color=Printer(name='Color',model='WF-C5890',ip='192.0.2.11',snmp_version='2c',oid_bw='',oid_color='')
        with patch('app.main.marker_values',side_effect=lambda ip,version,column:{'1.1':{4:23777,3:7,6:1}[column]}):
            discover_oid(mono)
            discover_oid(color)
        self.assertEqual(mono.oid_bw,'1.3.6.1.2.1.43.10.2.1.4.1.1')
        self.assertEqual(color.oid_bw,'')
        self.assertEqual(color.oid_color,'')
        self.assertTrue(color.oid_candidate)
    def test_existing_printers_discovery_preserves_manual_oids(self):
        token=self.login('admin','admin-password-for-tests')
        with Session(engine) as db:
            mono=Printer(name='Existing mono',model='WF-M5799',ip='192.0.2.90',snmp_version='2c',oid_bw='',oid_color='')
            color=Printer(name='Existing color',model='WF-C5890',ip='192.0.2.91',snmp_version='2c',oid_bw='1.2.3.4',oid_color='')
            db.add_all([mono,color]);db.commit()
            mono_id,color_id=mono.id,color.id
        with patch('app.main.marker_values',side_effect=lambda ip,version,column:{'1.1':{4:23777,3:7,6:1}[column]}):
            response=self.client.post('/printers/discover-all',data={'token':token})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:
            self.assertEqual(db.get(Printer,mono_id).oid_bw,'1.3.6.1.2.1.43.10.2.1.4.1.1')
            self.assertEqual(db.get(Printer,color_id).oid_bw,'1.2.3.4')
            self.assertTrue(db.get(Printer,color_id).oid_candidate)
            self.assertEqual(db.get(DiscoveryRun,1).running,0)
    def test_manual_collection_preserves_hourly_samples(self):
        token=self.login('admin','admin-password-for-tests')
        with patch('app.main.marker_values',return_value={}):
            response=self.client.post('/printers',data={'name':'Coleta','serial':'POLL001','model':'WF-M5299',
                'ip':'192.0.2.12','oid_bw':'1.3.6.1.2.1.43.10.2.1.4.1.1','token':token})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:pid=db.query(Printer).filter_by(serial='POLL001').one().id
        with patch('app.main.snmp',side_effect=[50,55]):
            for _ in range(2):
                response=self.client.post(f'/printers/{pid}/collect',data={'token':token})
                self.assertEqual(response.status_code,200)
        with Session(engine) as db:
            self.assertEqual(db.query(PollSample).filter_by(printer_id=pid).count(),2)
            self.assertEqual(db.query(Reading).filter_by(printer_id=pid).one().counter,55)
        listing=self.client.get('/printers')
        self.assertEqual(listing.status_code,200)
        self.assertIn('Contador P&B',listing.text)
        self.assertIn('<strong>55</strong>',listing.text)
        response=self.client.post('/settings',data={'fixed_fee':'0','jump_limit':'2000','collection_interval_hours':'6','token':token})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:self.assertEqual(db.get(BillingConfig,1).collection_interval_hours,6)
