import asyncio, csv, io, json, os, re, secrets, subprocess, hashlib
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from decimal import Decimal

import pdfplumber
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from passlib.hash import bcrypt
from sqlalchemy import create_engine, ForeignKey, Integer, String, Date, DateTime, Numeric, UniqueConstraint, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).resolve().parent.parent
engine = create_engine(os.environ['DATABASE_URL'], pool_pre_ping=True)
class Base(DeclarativeBase): pass
class Printer(Base):
    __tablename__='printers'
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(160))
    serial: Mapped[str]=mapped_column(String(80), unique=True, nullable=True)
    model: Mapped[str]=mapped_column(String(100), default='')
    ip: Mapped[str]=mapped_column(String(45), default='')
    raw_ip: Mapped[str]=mapped_column(String(80), default='')
    owner: Mapped[str]=mapped_column(String(100), default='')
    group_name: Mapped[str]=mapped_column(String(100), default='')
    oid_bw: Mapped[str]=mapped_column(String(100), default='')
    oid_color: Mapped[str]=mapped_column(String(100), default='')
    active: Mapped[int]=mapped_column(Integer, default=1)
class Reading(Base):
    __tablename__='readings'
    __table_args__=(UniqueConstraint('printer_id','day','kind'),)
    id: Mapped[int]=mapped_column(primary_key=True)
    printer_id: Mapped[int]=mapped_column(ForeignKey('printers.id'))
    day: Mapped[date]=mapped_column(Date)
    kind: Mapped[str]=mapped_column(String(10))
    counter: Mapped[int]=mapped_column(Integer)
    source: Mapped[str]=mapped_column(String(30))
    printer: Mapped[Printer]=relationship()
class User(Base):
    __tablename__='users'
    id: Mapped[int]=mapped_column(primary_key=True)
    username: Mapped[str]=mapped_column(String(80), unique=True)
    password_hash: Mapped[str]=mapped_column(String(150))
    role: Mapped[str]=mapped_column(String(20))
class Invoice(Base):
    __tablename__='invoices'
    id: Mapped[int]=mapped_column(primary_key=True)
    month: Mapped[str]=mapped_column(String(7))
    filename: Mapped[str]=mapped_column(String(160))
    sha256: Mapped[str]=mapped_column(String(64), unique=True)
    uploaded_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
class InvoiceLine(Base):
    __tablename__='invoice_lines'
    id: Mapped[int]=mapped_column(primary_key=True)
    invoice_id: Mapped[int]=mapped_column(ForeignKey('invoices.id'))
    serial: Mapped[str]=mapped_column(String(80))
    kind: Mapped[str]=mapped_column(String(10))
    previous: Mapped[int | None]=mapped_column(Integer, nullable=True)
    current: Mapped[int]=mapped_column(Integer)
    quantity: Mapped[int]=mapped_column(Integer)
    amount: Mapped[Decimal]=mapped_column(Numeric(12,2))
    previous_day: Mapped[date | None]=mapped_column(Date, nullable=True)
    current_day: Mapped[date]=mapped_column(Date)

VALID_OID=re.compile(r'^\.?\d+(?:\.\d+)+$')
def logged(request): return request.session.get('user')
def authorize(request, admin=False):
    u=logged(request)
    if not u: raise HTTPException(401,'Faça login')
    if admin and u['role']!='admin': raise HTTPException(403,'Somente administrador')
    return u
def csrf(request, token):
    if not secrets.compare_digest(request.session.get('csrf',''),token): raise HTTPException(403,'Formulário expirado')
def page(request,name,**kwargs):
    if 'csrf' not in request.session:request.session['csrf']=secrets.token_urlsafe(24)
    return templates.TemplateResponse(request,name,{'user':logged(request),'csrf':request.session['csrf'],**kwargs})
def redirect(path):return RedirectResponse(path,status_code=303)
def seed():
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first_run = not db.scalar(select(func.count(User.id)))
        for name,role,var in [('admin','admin','ADMIN_PASSWORD'),('consulta','viewer','VIEWER_PASSWORD')]:
            if not db.scalar(select(User).where(User.username==name)):
                db.add(User(username=name,role=role,password_hash=bcrypt.hash(os.environ[var])))
        if first_run:
            for row in json.loads((ROOT/'data/inventory.json').read_text()):
                db.add(Printer(**{k:v for k,v in row.items() if k in ('name','serial','model','ip','raw_ip','owner','group_name') and (k!='serial' or v)}))
        db.commit()
def snmp(ip,oid):
    if not ip or not VALID_OID.fullmatch(oid):return None
    try:
        p=subprocess.run(['snmpget','-v','2c','-c',os.environ.get('SNMP_COMMUNITY','public'),'-Oqv','-t','2','-r','0',ip,oid],capture_output=True,text=True,timeout=5)
        m=re.search(r'(?:Counter32:|Counter64:|INTEGER:)?\s*(\d+)\s*$',p.stdout.strip())
        return int(m.group(1)) if p.returncode==0 and m else None
    except (subprocess.TimeoutExpired,OSError):return None
def collect():
    today=date.today()
    with Session(engine) as db:
        for p in db.scalars(select(Printer).where(Printer.active==1)).all():
            for kind,oid in [('bw',p.oid_bw),('color',p.oid_color)]:
                if not oid or not p.ip:continue
                val=snmp(p.ip,oid)
                if val is None:continue
                item=db.scalar(select(Reading).where(Reading.printer_id==p.id,Reading.day==today,Reading.kind==kind))
                if item:item.counter=val;item.source='snmp'
                else:db.add(Reading(printer_id=p.id,day=today,kind=kind,counter=val,source='snmp'))
        db.commit()
async def scheduler():
    while True:
        now=datetime.now(timezone.utc)
        target=now.replace(hour=int(os.environ.get('COLLECTION_HOUR_UTC','12'))%24,minute=0,second=0,microsecond=0)
        if target<=now:target+=timedelta(days=1)
        await asyncio.sleep((target-now).total_seconds())
        await asyncio.to_thread(collect)
@asynccontextmanager
async def lifespan(app):
    seed();task=asyncio.create_task(scheduler())
    yield
    task.cancel()
app=FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware,secret_key=os.environ['SESSION_SECRET'],same_site='lax',https_only=os.environ.get('HTTPS_ONLY')=='1')
templates=Jinja2Templates(directory=str(ROOT/'app/templates'))
@app.get('/health')
def health():return {'ok':True}
@app.get('/login',response_class=HTMLResponse)
def login_page(request:Request):return page(request,'login.html')
@app.post('/login')
def login(request:Request,username:str=Form(),password:str=Form(),token:str=Form()):
    csrf(request,token)
    with Session(engine) as db:
        u=db.scalar(select(User).where(User.username==username))
        if not u or not bcrypt.verify(password,u.password_hash):return page(request,'login.html',error='Credenciais inválidas')
        request.session.clear();request.session['user']={'name':u.username,'role':u.role};request.session['csrf']=secrets.token_urlsafe(24)
    return redirect('/')
@app.post('/logout')
def logout(request:Request,token:str=Form()):csrf(request,token);request.session.clear();return redirect('/login')
def series(db, start, end, printer_id=None, group=None):
    q=select(Reading,Printer).join(Printer).where(Reading.day<=end)
    if printer_id:q=q.where(Printer.id==printer_id)
    if group:q=q.where(Printer.group_name==group)
    rows=db.execute(q).all();by={}
    for r,p in rows:by.setdefault((p.id,r.kind),[]).append((r,p))
    result=[]
    for _,items in by.items():
        items.sort(key=lambda x:x[0].day)
        for (prev,_),(cur,p) in zip(items,items[1:]):
            if not start<=cur.day<=end:continue
            delta=cur.counter-prev.counter
            result.append({'printer':p.name,'serial':p.serial or '', 'group':p.group_name,'kind':cur.kind,'day':cur.day,'quantity':delta if delta>=0 else None,'status':'OK' if delta>=0 else 'Contador reduzido','gap':(cur.day-prev.day).days})
    return sorted(result,key=lambda x:(x['day'],x['printer']),reverse=True)
@app.get('/',response_class=HTMLResponse)
def home(request:Request, start:date|None=None,end:date|None=None,printer_id:int|None=None,group:str|None=None):
    authorize(request)
    end=end or date.today();start=start or end-timedelta(days=30)
    if start>end or (end-start).days>3660:raise HTTPException(400,'Período inválido')
    with Session(engine) as db:
        printers=db.scalars(select(Printer).order_by(Printer.name)).all()
        groups=sorted({p.group_name for p in printers if p.group_name})
        rows=series(db,start,end,printer_id,group)
        def total(a,b):return sum(r['quantity'] or 0 for r in series(db,a,b,printer_id,group))
        today=date.today();current=total(today,today);yesterday=total(today-timedelta(days=1),today-timedelta(days=1))
        week=total(today-timedelta(days=6),today);prior_week=total(today-timedelta(days=13),today-timedelta(days=7))
        month_start=today.replace(day=1);prior_end=month_start-timedelta(days=1)
        month=total(month_start,today);prior_month=total(prior_end.replace(day=1),prior_end)
        return page(request,'dashboard.html',printers=printers,groups=groups,rows=rows,start=start,end=end,printer_id=printer_id,group=group,metrics=[('Hoje',current,yesterday),('Últimos 7 dias',week,prior_week),('Mês atual',month,prior_month)],total=sum(r['quantity'] or 0 for r in rows))
@app.get('/export.csv')
def export(request:Request,start:date,end:date,printer_id:int|None=None,group:str|None=None):
    authorize(request)
    if start>end or (end-start).days>3660:raise HTTPException(400,'Período inválido')
    with Session(engine) as db:rows=series(db,start,end,printer_id,group)
    out=io.StringIO();writer=csv.writer(out);writer.writerow(['Data','Impressora','Série','Responsável','Tipo','Quantidade','Dias entre leituras','Status'])
    for r in rows:
        writer.writerow(["'"+str(r[k]) if isinstance(r[k],str) and r[k].startswith(('=','+','-','@')) else r[k] for k in ('day','printer','serial','group','kind','quantity','gap','status')])
    return StreamingResponse(iter([out.getvalue().encode('utf-8-sig')]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="tiragem.csv"'})
@app.get('/printers',response_class=HTMLResponse)
def printers_page(request:Request):
    authorize(request,True)
    with Session(engine) as db:return page(request,'printers.html',printers=db.scalars(select(Printer).order_by(Printer.name)).all())
def printer_fields(db, name, serial, model, ip, owner, group_name, oid_bw, oid_color, exclude_id=None):
    import ipaddress
    values = dict(name=name.strip(), serial=serial.strip() or None, model=model.strip(),
                  ip=ip.strip(), owner=owner.strip(), group_name=group_name.strip(),
                  oid_bw=oid_bw.strip(), oid_color=oid_color.strip())
    if not values['name'] or len(values['name'])>160:
        raise HTTPException(400,'Informe um nome de até 160 caracteres')
    limits={'serial':80,'model':100,'owner':100,'group_name':100,'oid_bw':100,'oid_color':100}
    if any(len(values[key] or '')>limit for key,limit in limits.items()):
        raise HTTPException(400,'Um dos campos excede o tamanho permitido')
    if values['ip']:
        try:ipaddress.ip_address(values['ip'])
        except ValueError:raise HTTPException(400,'IP inválido')
    if any(values[k] and not VALID_OID.fullmatch(values[k]) for k in ('oid_bw','oid_color')):
        raise HTTPException(400,'OID inválido')
    if values['serial']:
        existing=db.scalar(select(Printer).where(Printer.serial==values['serial']))
        if existing and existing.id!=exclude_id:
            raise HTTPException(400,'Número de série já cadastrado')
    return values
@app.post('/printers')
def add_printer(request:Request,name:str=Form(),serial:str=Form(''),model:str=Form(''),ip:str=Form(''),owner:str=Form(''),group_name:str=Form(''),oid_bw:str=Form(''),oid_color:str=Form(''),token:str=Form()):
    authorize(request,True);csrf(request,token)
    with Session(engine) as db:
        values=printer_fields(db,name,serial,model,ip,owner,group_name,oid_bw,oid_color)
        db.add(Printer(**values,raw_ip=values['ip']))
        db.commit()
    return redirect('/printers')
@app.post('/printers/{printer_id}')
def edit_printer(request:Request,printer_id:int,name:str=Form(),serial:str=Form(''),model:str=Form(''),ip:str=Form(''),owner:str=Form(''),group_name:str=Form(''),oid_bw:str=Form(''),oid_color:str=Form(''),token:str=Form()):
    authorize(request,True);csrf(request,token)
    with Session(engine) as db:
        p=db.get(Printer,printer_id)
        if not p:raise HTTPException(404)
        values=printer_fields(db,name,serial,model,ip,owner,group_name,oid_bw,oid_color,p.id)
        for key,value in values.items():setattr(p,key,value)
        db.commit()
    return redirect('/printers')
@app.post('/printers/{printer_id}/status')
def printer_status(request:Request,printer_id:int,active:int=Form(),token:str=Form()):
    authorize(request,True);csrf(request,token)
    if active not in (0,1):raise HTTPException(400,'Status inválido')
    with Session(engine) as db:
        p=db.get(Printer,printer_id)
        if not p:raise HTTPException(404)
        p.active=active
        db.commit()
    return redirect('/printers')
@app.post('/printers/{printer_id}/delete')
def delete_printer(request:Request,printer_id:int,token:str=Form()):
    authorize(request,True);csrf(request,token)
    with Session(engine) as db:
        p=db.get(Printer,printer_id)
        if not p:raise HTTPException(404)
        if db.scalar(select(Reading.id).where(Reading.printer_id==printer_id).limit(1)):
            raise HTTPException(409,'Há leituras registradas. Desative a impressora para preservar o histórico.')
        db.delete(p)
        db.commit()
    return redirect('/printers')
@app.post('/readings')
def manual(request:Request,printer_id:int=Form(),day:date=Form(),kind:str=Form(),counter:int=Form(),token:str=Form()):
    authorize(request,True);csrf(request,token)
    if kind not in ('bw','color') or counter<0:raise HTTPException(400)
    with Session(engine) as db:
        if not db.get(Printer,printer_id):raise HTTPException(404)
        r=db.scalar(select(Reading).where(Reading.printer_id==printer_id,Reading.day==day,Reading.kind==kind))
        if r:r.counter=counter;r.source='manual'
        else:db.add(Reading(printer_id=printer_id,day=day,kind=kind,counter=counter,source='manual'))
        db.commit()
    return redirect('/printers')
@app.post('/collect')
async def collect_now(request:Request,token:str=Form()):
    authorize(request,True);csrf(request,token)
    await asyncio.to_thread(collect)
    return redirect('/printers')
# Parse the supplier's text PDF. Reject unrecognized layouts instead of inventing values.
LINE=re.compile(r'^\s*(.+?)\s+(\S+)\s+([A-Z0-9]{7,})\s+(\d+)\s+(\d{2}/\d{2}/\d{4})\s+(?:(\d+)\s+(\d{2}/\d{2}/\d{4})\s+)?(\d+)\s+([\d.,]+)\s*$')
def parse_pdf(blob):
    with pdfplumber.open(io.BytesIO(blob)) as pdf:text='\n'.join(p.extract_text(layout=False) or '' for p in pdf.pages)
    m=re.search(r'mês:\s*(\d{1,2})/(\d{4})',text,re.I)
    if not m:raise ValueError('Mês de referência não identificado')
    month=f'{int(m.group(2)):04d}-{int(m.group(1)):02d}';kind=None;lines=[]
    for raw in text.splitlines():
        if 'Tipo de tiragem: COPIA/IMP-A4COR' in raw:kind='color';continue
        if 'Tipo de tiragem: COPIA/IMP-A4PB' in raw:kind='bw';continue
        match=LINE.match(raw)
        if kind and match:
            name,model,serial,current,current_day,previous,previous_day,quantity,amount=match.groups()
            lines.append(dict(serial=serial,kind=kind,current=int(current),current_day=datetime.strptime(current_day,'%d/%m/%Y').date(),previous=int(previous) if previous else None,previous_day=datetime.strptime(previous_day,'%d/%m/%Y').date() if previous_day else None,quantity=int(quantity),amount=Decimal(amount.replace('.','').replace(',','.'))))
    if not lines:raise ValueError('Nenhuma linha de impressora reconhecida. Verifique o formato do PDF.')
    total_match=re.search(r'Total do endereço de instalação:\s*(\d+)',text)
    if total_match and sum(x['quantity'] for x in lines)!=int(total_match.group(1)):
        raise ValueError('A soma das linhas difere do total de páginas do PDF')
    if len({(x['serial'],x['kind']) for x in lines})!=len(lines):
        raise ValueError('Linhas duplicadas para a mesma série e tipo')
    return month,lines
@app.get('/invoices',response_class=HTMLResponse)
def invoices(request:Request):
    authorize(request)
    with Session(engine) as db:return page(request,'invoices.html',invoices=db.scalars(select(Invoice).order_by(Invoice.uploaded_at.desc())).all())
@app.post('/invoices')
async def upload_invoice(request:Request,file:UploadFile=File(),token:str=Form()):
    authorize(request,True);csrf(request,token)
    blob=await file.read(5_000_001)
    if len(blob)>5_000_000 or not blob.startswith(b'%PDF-'):raise HTTPException(400,'Envie um PDF de até 5 MB')
    try:month,lines=parse_pdf(blob)
    except Exception as exc:raise HTTPException(400,f'PDF não reconhecido: {exc}')
    digest=hashlib.sha256(blob).hexdigest()
    with Session(engine) as db:
        existing=db.scalar(select(Invoice).where(Invoice.sha256==digest))
        if existing:return redirect(f'/invoices/{existing.id}')
        inv=Invoice(month=month,filename=Path(file.filename or 'demonstrativo.pdf').name[:160],sha256=digest)
        db.add(inv);db.flush()
        for row in lines:db.add(InvoiceLine(invoice_id=inv.id,**row))
        db.commit();iid=inv.id
    directory=ROOT/'uploads';directory.mkdir(exist_ok=True)
    (directory/f'{digest}.pdf').write_bytes(blob)
    return redirect(f'/invoices/{iid}')
def nearest(db,pid,kind,day):
    return db.scalar(select(Reading).where(Reading.printer_id==pid,Reading.kind==kind,Reading.day<=day).order_by(Reading.day.desc()).limit(1))
@app.get('/invoices/{iid}',response_class=HTMLResponse)
def invoice_detail(request:Request,iid:int):
    authorize(request)
    with Session(engine) as db:
        inv=db.get(Invoice,iid)
        if not inv:raise HTTPException(404)
        results=[]
        for line in db.scalars(select(InvoiceLine).where(InvoiceLine.invoice_id==iid).order_by(InvoiceLine.serial,InvoiceLine.kind)):
            p=db.scalar(select(Printer).where(Printer.serial==line.serial))
            a=nearest(db,p.id,line.kind,line.previous_day) if p and line.previous_day else None
            b=nearest(db,p.id,line.kind,line.current_day) if p else None
            diff=b.counter-a.counter-line.quantity if a and b else None
            status=('Série não cadastrada' if not p else 'Leituras locais insuficientes' if diff is None else 'Conferido' if diff==0 and a.day==line.previous_day and b.day==line.current_day else 'Divergência' if a.day==line.previous_day and b.day==line.current_day else 'Datas não coincidem')
            results.append({'line':line,'printer':p,'a':a,'b':b,'diff':diff,'status':status,'arithmetic':(line.current-line.previous-line.quantity) if line.previous is not None else None})
        return page(request,'invoice.html',invoice=inv,rows=results)
@app.get('/invoices/{iid}/pdf')
def invoice_file(request:Request,iid:int):
    authorize(request)
    with Session(engine) as db:
        inv=db.get(Invoice,iid)
        if not inv:raise HTTPException(404)
        path=ROOT/'uploads'/f'{inv.sha256}.pdf'
        if not path.is_file():raise HTTPException(404)
    from fastapi.responses import FileResponse
    return FileResponse(path,media_type='application/pdf',filename='demonstrativo.pdf')
