"""Pure calculation and CSV import helpers."""
import csv
import io
import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation


def usage(previous: int, current: int, rollover: int | None = None):
    if current >= previous:
        return current - previous, 'ok'
    if rollover and 0 <= previous < rollover and 0 <= current < rollover:
        return rollover - previous + current, 'rollover'
    return None, 'reset'


def month_bounds(value: str):
    year, month = (int(x) for x in value.split('-'))
    return date(year, month, 1), date(year + (month == 12), month % 12 + 1, 1)


def money(value):
    if isinstance(value, Decimal):return value
    value=str(value).strip().replace('R$', '').replace(' ', '')
    if ',' in value:value=value.replace('.', '').replace(',', '.')
    try:return Decimal(value)
    except InvalidOperation as exc:raise ValueError('Valor monetário inválido') from exc


def parse_librenms_csv(blob: bytes):
    """Columns: date|timestamp, serial|hostname|ip, bw/color or kind+counter."""
    try:text=blob.decode('utf-8-sig')
    except UnicodeDecodeError as exc:raise ValueError('CSV deve estar em UTF-8') from exc
    if not text.strip():raise ValueError('CSV vazio')
    try:dialect=csv.Sniffer().sniff(text[:4096], delimiters=',;\t')
    except csv.Error:dialect=csv.excel
    reader=csv.DictReader(io.StringIO(text,newline=''),dialect=dialect)
    if not reader.fieldnames:raise ValueError('Cabeçalho ausente')
    aliases={'date':['date','day','timestamp','datetime','data'], 'serial':['serial','serial_number','serie','número de série'], 'hostname':['hostname','host','device','dispositivo'], 'ip':['ip','ipv4','ip_address'], 'bw':['bw','pb','mono','black','preto_branco'], 'color':['color','colour','cor'], 'kind':['kind','type','tipo'], 'counter':['counter','value','contador']}
    fields={str(k).strip().lower():k for k in reader.fieldnames}
    pick=lambda name:next((fields[x] for x in aliases[name] if x in fields),None)
    dt=pick('date');ident=next((pick(x) for x in ('serial','hostname','ip') if pick(x)),None)
    bw=pick('bw');color=pick('color');kind=pick('kind');counter=pick('counter')
    if not dt or not ident or not (bw or color or (kind and counter)):
        raise ValueError('Colunas necessárias: date, serial/hostname/ip e bw/color ou kind+counter')
    result=[]
    for number,row in enumerate(reader,start=2):
        if not any(str(v or '').strip() for v in row.values()):continue
        identifier=str(row.get(ident) or '').strip()
        if not identifier:raise ValueError(f'Linha {number}: impressora vazia')
        value=str(row.get(dt) or '').strip()
        try:day=datetime.strptime(value,'%d/%m/%Y').date() if re.fullmatch(r'\d{2}/\d{2}/\d{4}',value) else date.fromisoformat(value[:10])
        except ValueError as exc:raise ValueError(f'Linha {number}: data inválida') from exc
        pairs=([(row.get(kind),row.get(counter))] if kind and counter else [(typ,row.get(col)) for typ,col in (('bw',bw),('color',color)) if col])
        for typ,val in pairs:
            if val is None or str(val).strip()=='':continue
            typ=str(typ).strip().lower()
            typ={'pb':'bw','mono':'bw','preto_branco':'bw','cor':'color','colour':'color'}.get(typ,typ)
            if typ not in ('bw','color'):raise ValueError(f'Linha {number}: tipo desconhecido')
            if not re.fullmatch(r'\d+',str(val).strip()):raise ValueError(f'Linha {number}: contador inválido')
            result.append((identifier,day,typ,int(str(val).strip())))
    if not result:raise ValueError('CSV sem leituras')
    return result
