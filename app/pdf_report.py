"""Printable version of the same usage rows displayed on the dashboard."""
import io
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import reportlab
from pathlib import Path

FONT_PATH=Path(reportlab.__file__).parent/'fonts'/'Vera.ttf'
pdfmetrics.registerFont(TTFont('ReportVera',str(FONT_PATH)))


def build_report_pdf(rows,start,end,printer,group):
    out=io.BytesIO()
    paper=landscape(A4)
    doc=SimpleDocTemplate(out,pagesize=paper,rightMargin=28,leftMargin=28,
                          topMargin=32,bottomMargin=36,title='Relatório de tiragem')
    styles=getSampleStyleSheet()
    title=ParagraphStyle('ReportTitle',parent=styles['Title'],fontName='ReportVera',fontSize=17,
                         leading=22,textColor=colors.HexColor('#123849'),spaceAfter=10)
    normal=ParagraphStyle('ReportBody',parent=styles['Normal'],fontName='ReportVera',fontSize=8,
                          leading=11,textColor=colors.HexColor('#263b49'))
    cell=ParagraphStyle('ReportCell',parent=normal,fontSize=7,leading=9)
    right=ParagraphStyle('ReportRight',parent=cell,alignment=TA_RIGHT)
    heading=ParagraphStyle('ReportHead',parent=cell,textColor=colors.white)
    story=[Paragraph('Relatório de tiragem',title),
           Paragraph(f'Período: {start:%d/%m/%Y} a {end:%d/%m/%Y}  |  '
                     f'Impressora: {escape(printer)}  |  Responsável: {escape(group)}',normal),Spacer(1,10)]
    counted=sum(row['quantity'] or 0 for row in rows)
    story.append(Paragraph(f'<b>Total: {counted:,} páginas</b>  |  {len(rows)} registros'.replace(',','.'),normal))
    story.append(Spacer(1,6))
    story.append(Paragraph('Quantidade = diferença entre leituras consecutivas. Uma primeira leitura estabelece a base; '
                           'intervalos sem coleta aparecem em Dias.',normal))
    story.append(Spacer(1,12))
    headers=['Data','Impressora','Série','Responsável','Tipo','Páginas','Dias','Situação']
    data=[[Paragraph(h,heading) for h in headers]]
    for row in rows:
        values=[str(row['day']),row['printer'],row['serial'],row['group'],
                'Colorido' if row['kind']=='color' else 'P&B',
                '—' if row['quantity'] is None else f"{row['quantity']:,}".replace(',','.'),
                str(row['gap']),row['status']]
        data.append([Paragraph(escape(str(v or '')),right if i in (5,6) else cell)
                     for i,v in enumerate(values)])
    if not rows:data.append([Paragraph('Nenhum consumo calculado para os filtros selecionados.',cell)]+['']*7)
    table=LongTable(data,colWidths=[70,160,105,140,65,75,45,115],repeatRows=1,hAlign='LEFT')
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#123849')),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f0f6f8')]),
        ('BOTTOMPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LINEBELOW',(0,-1),(-1,-1),0.3,colors.HexColor('#dce7ea')),
    ]))
    story.append(table)

    def footer(canvas,doc):
        canvas.saveState()
        canvas.setFont('ReportVera',8)
        canvas.setFillColor(colors.HexColor('#58717d'))
        canvas.drawString(28,20,'Tiragem de impressoras  |  Contadores apurados por intervalo')
        canvas.drawRightString(paper[0]-28,20,f'Página {doc.page}')
        canvas.restoreState()

    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return out.getvalue()
