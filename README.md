# Tiragem de impressoras

Aplicação local em FastAPI, PostgreSQL e Docker Compose para registrar contadores SNMP, comparar períodos e conferir demonstrativos PDF. O banco e os PDFs ficam em volumes Docker persistentes.

## Instalação

1. Copie `.env.example` para `.env` e gere segredos longos e diferentes para `POSTGRES_PASSWORD`, `SESSION_SECRET`, `ADMIN_PASSWORD` e `VIEWER_PASSWORD` (`openssl rand -hex 32`). Nunca envie `.env` ao Git.
2. Dentro da pasta do repositório, execute `docker compose up -d --build`.
3. Consulte `docker compose ps` e `curl http://127.0.0.1:8000/health`. O bind padrão aceita apenas conexões locais. Para acesso de rede, configure `BIND_ADDRESS` e proteja a aplicação com HTTPS e regras de firewall.
4. Entre com `admin` ou `consulta` usando a senha correspondente do `.env`. As contas são criadas na primeira inicialização; alterar as variáveis depois não redefine senhas já cadastradas.

## Impressoras

A página **Impressoras** mostra uma tabela com nome, modelo, série, IP, proprietário, responsável, último contador acumulado P&B e cor com data e origem, e ações. O contador exibido é uma leitura acumulada, não a quantidade impressa no dia; uma coluna sem leitura mostra um traço. Cadastro e edição têm páginas separadas. Uma impressora desativada mantém o histórico e deixa de ser coletada. Exclusão definitiva só é permitida quando não há leituras associadas.

No cadastro, o app consulta a Printer MIB da impressora. Para impressoras já cadastradas, o administrador pode usar **Buscar OIDs de todas** na lista; a busca roda em segundo plano e mostra o progresso após atualizar a página. Também há **Buscar OIDs novamente** na edição. Somente para um modelo Epson `WF-M` monocromático, com um único contador em unidade de impressões e um colorante, ele preenche automaticamente o OID P&B. Para modelos coloridos, o OID total é exibido como candidato; configure os contadores separados depois de conferir painel, fabricante e cobrança. Não há dedução confiável de P&B/cor a partir de um contador genérico. Uma falha SNMP não bloqueia o cadastro nem a busca das demais impressoras. Valores inseridos manualmente são preservados.

As impressoras recebem SNMP v2c por padrão, usando `SNMP_COMMUNITY`. Para impressoras que respondem apenas em SNMPv1, selecione v1 na edição; v1 usa a mesma comunidade configurada para v2c. Para v3, use as variáveis `SNMPV3_USER`, `SNMPV3_AUTH_PASSWORD` e `SNMPV3_PRIV_PASSWORD` e selecione v3 no cadastro. Configure uma comunidade/usuário de leitura com acesso restrito. Docker precisa alcançar o endereço da impressora. Antes de associar um contador SNMP à cobrança, confira se ele corresponde ao contador exibido e faturado.

## Coleta e relatórios

Em **Configurações**, selecione a coleta automática a cada 1 a 168 horas (padrão 24). A última execução é persistida no banco. Na primeira inicialização após instalar esta versão, a coleta programada pode começar imediatamente. Use **Capturar todas agora** ou **Capturar** na linha de uma impressora para coleta manual. Cada amostra com horário é gravada em `poll_samples`; a tabela de leituras diárias guarda a última amostra do dia para relatórios.

Uma primeira leitura estabelece a base. Os relatórios comparam leituras em datas consecutivas e atribuem o consumo à data mais recente. Intervalos sem amostras diárias são mostrados; a quantidade do intervalo não pode ser atribuída a cada dia anterior. Se o contador diminuir, o app registra um alerta e não contabiliza a diferença como impressão. Configure um limite de virada apenas se ele for conhecido. CSV dos relatórios é exportado em UTF-8.

A importação de histórico aceita CSV UTF-8 com `date`/`timestamp`, `serial`/`hostname`/`ip` e `bw`/`color`, ou `kind` e `counter`. Os valores precisam ser **acumulados**. A importação não substitui uma leitura existente com valor diferente; impressoras não identificadas ou ambiguidades interrompem toda a importação. O formato de exportação do LibreNMS pode exigir adaptação.

O dashboard mostra consumo por dia, impressora e responsável e alertas de falha de coleta, lacunas, queda de contador e salto acima do limiar. Alertas ficam no aplicativo; envio por e-mail ainda não está implementado.

## Conferência de demonstrativos

O administrador envia um PDF em **Demonstrativos**. O app conserva o original e confere as linhas por número de série, tipo e datas do fornecedor. O valor calculado com tarifas/franquias cadastradas fica separado do valor cobrado. Uma leitura ausente ou em outra data não aprova automaticamente a cobrança. O parser aceita o layout do demonstrativo usado no projeto e rejeita outros layouts para revisão.

## Operação

Faça backup dos volumes `pgdata` e `uploads` antes de atualizar. O esquema anterior recebe colunas e tabelas novas na inicialização sem remover o histórico. A auditoria mostra as últimas alterações administrativas. Para executar testes locais: `pip install -r requirements-dev.txt` e `python3 -m unittest discover -s tests -v`. A coleta SNMP e as regras de cobrança devem ser conferidas com os equipamentos e o contrato reais antes do uso operacional.
