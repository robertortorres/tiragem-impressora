# Tiragem de impressoras · Medsel

App local em FastAPI, PostgreSQL e Docker Compose. Importa inicialmente as 24 posições da planilha fornecida; mantém o proprietário, responsável, modelo, IP original e número de série. A tela de administração permite cadastrar e editar impressoras (nome, modelo, série, IP, proprietário, responsável e OIDs), desativar/reativar equipamentos e excluir definitivamente os que não têm leituras. O PDF de setembro de 2026 foi usado para validar o formato do importador (22 linhas, 36.239 páginas e R$ 2.480,65 de tiragem variável).

## Publicar no GitHub

Extraia o ZIP e versiona a pasta `impressoras-app` como repositório. O arquivo `.env` com senhas é ignorado pelo Git; publique somente `.env.example`. Para um repositório novo, dentro da pasta, execute `git init`, `git add .`, `git commit -m "Initial printer monitoring app"`, configure a URL com `git remote add origin URL_DO_REPOSITORIO` e faça `git push -u origin main` após criar a branch principal (`git branch -M main`). Não inclua PDFs recebidos nem volumes do PostgreSQL no repositório.

## Iniciar

1. Copie `.env.example` para `.env` e substitua as quatro senhas/segredos. Gere valores longos e únicos (`openssl rand -hex 32`).
2. Execute `docker compose up -d --build` dentro desta pasta.
3. Acesse `http://localhost:8000`. Usuários iniciais: `admin` e `consulta`, com as senhas do `.env`. A porta só escuta no endereço configurado em `BIND_ADDRESS`, inicialmente localhost.
4. Use um proxy HTTPS com controle de acesso caso o serviço fique disponível fora do computador. Nesse caso, configure `HTTPS_ONLY=1` no serviço web e faça backup dos volumes `pgdata` e `uploads`.

## Gerenciar impressoras

O administrador pode adicionar e editar impressoras em **Impressoras**. A desativação suspende a coleta SNMP sem perder leituras ou relatórios; reativar retoma a coleta. A exclusão definitiva só é aceita quando ainda não há leituras associadas. Se houver histórico, desative. Séries preenchidas devem ser únicas, para que o PDF da locadora seja associado à impressora correta. A planilha é importada apenas na criação inicial do banco; uma exclusão não é revertida por um reinício do app.

## Configurar a coleta

- Revise as entradas em **Impressoras**. Somente 10 dos 24 IPs da planilha são endereços IPv4 válidos como digitados; 21 posições têm série. A linha “Sala 05 Color” tem dados de modelo/IP, mas nenhuma série; outras impressoras Medsel podem não aparecer no PDF da locadora. Não adivinhamos IP nem série.
- Para cada impressora, identifique com `snmpwalk` os OIDs que devolvem contadores acumulados **separados** de P&B e colorido. Defina `OID P&B` e `OID cor` na tela. OIDs variam por modelo; um contador genérico de páginas pode incluir tipos mistos e causar cobrança equivocada.
- A imagem inclui `snmpget` (SNMP v2c). A comunidade vem de `SNMP_COMMUNITY`; configure uma comunidade de leitura com acesso restrito. Docker precisa alcançar a rede das impressoras. A coleta ocorre diariamente no horário UTC configurado (padrão 12:00 UTC = 09:00 em São Paulo durante setembro) e pode ser disparada manualmente.
- Insira uma leitura inicial manual para estabelecer a base. A coleta grava um contador acumulado por impressora, tipo e dia; repetição no mesmo dia atualiza a leitura. Diferencial negativo indica reinício/troca do equipamento e não é somado como consumo.

## Relatórios e conferência

Selecione período, impressora e/ou grupo responsável; exporte CSV. Os cards comparam hoje com ontem, últimos 7 dias com os 7 anteriores e mês corrente com o mês calendário anterior. Enquanto não houver leituras diárias consecutivas, os totais por dia são parciais: a diferença entre duas coletas é atribuída ao último dia, com o intervalo mostrado na coluna “Dias”.

Em **Demonstrativos**, o admin envia o PDF da Maquim. O sistema preserva o original, identifica mês, série, P&B/cor, leituras anteriores e atuais, quantidade e valor, verifica o total de páginas informado e confere a aritmética por linha. Compara cada linha às leituras internas na mesma data da medição do fornecedor; leituras ausentes ou em outras datas geram pendência, nunca aprovação automática. PDF diferente do layout de exemplo é rejeitado para revisão manual. PDFs duplicados são identificados pelo hash SHA-256.

O PDF fornecido informa leituras de **10/08/2026 a 10/09/2026**, apesar de ser o demonstrativo de competência 09/2026. Há 22 linhas (2 coloridas, 20 P&B), 36.239 páginas. Os valores variáveis somam R$ 2.480,65; parcela fixa R$ 1.530,64; faturamento R$ 4.011,29. Essas parcelas ainda não são extraídas para conciliação financeira automática.

## Limites desta primeira versão

Não há dados históricos do LibreNMS importados: sem isso, o dashboard começa vazio. Os contadores SNMP e conectividade precisam de validação em cada modelo. Acesso para terceiros deve passar por HTTPS; não publique a porta HTTP diretamente. A criação inicial das duas contas usa as senhas do `.env` apenas na primeira subida: alterar essas variáveis depois não redefine contas existentes. Não há ainda tela de gestão de senhas/usuários, migrações de esquema, trilha de auditoria ou alertas automáticos.

Próximas melhorias úteis: importar histórico do LibreNMS; leitura SNMPv3 e detecção de contador reiniciado; cadastro de custo por página e franquia; alertas de coleta ausente ou salto incomum; log de alterações; gráfico de evolução por impressora e responsável; conciliação de parcela fixa e tarifas.
