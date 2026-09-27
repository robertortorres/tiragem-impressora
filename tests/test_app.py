"""End-to-end checks using a disposable SQLite database and the supplied PDF."""
import os
import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

_dir=tempfile.TemporaryDirectory()
os.environ['DATABASE_URL']='sqlite:///'+str(Path(_dir.name)/'app.db')
os.environ['SESSION_SECRET']='integration-test-secret'
os.environ['ADMIN_PASSWORD']='admin-password-for-tests'
os.environ['VIEWER_PASSWORD']='viewer-password-for-tests'
from app.main import app,engine,Printer,Reading

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
        response=self.client.post('/printers',data={'name':'Teste','serial':'TEST-SERIAL','token':token})
        self.assertEqual(response.status_code,200)
        with Session(engine) as db:pid=db.query(Printer).filter_by(serial='TEST-SERIAL').one().id
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
        self.assertEqual(self.client.get('/printers').status_code,403)
        self.assertEqual(self.client.post('/printers',data={'name':'Bloqueada','token':token}).status_code,403)
        self.assertEqual(self.client.get('/').status_code,200)
