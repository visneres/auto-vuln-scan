import os
import sys
import csv
import html
import json
import time
import socket
import fcntl

from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

from lxml import etree

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError


# ============================================================
# CONFIGURAÇÕES
# ============================================================

SOCKET_PATH = "/run/gvmd/gvmd.sock"

USER = os.getenv(
    "GVM_USER",
    "admin"
)

PASSWORD = os.getenv(
    "GVM_PASSWORD"
)

NOME_TASK = os.getenv(
    "GVM_TASK_NAME",
    "Scan-Metasploitable3-Full-and-Fast"
)

NOME_TARGET = os.getenv(
    "GVM_TARGET_NAME",
    "Metasploitable3-Windows"
)

IP_ALVO = os.getenv(
    "GVM_TARGET_IP",
    "192.168.70.20"
)

START_SCAN = (
    os.getenv(
        "START_SCAN",
        "0"
    ) == "1"
)

REPORT_ID_EXISTENTE = os.getenv(
    "REPORT_ID"
)

INTERVALO_MONITORAMENTO = int(
    os.getenv(
        "INTERVALO_MONITORAMENTO",
        "20"
    )
)

MAX_FALHAS_MONITORAMENTO = int(
    os.getenv(
        "MAX_FALHAS_MONITORAMENTO",
        "15"
    )
)

MAX_FALHAS_PROCESSAMENTO = int(
    os.getenv(
        "MAX_FALHAS_PROCESSAMENTO",
        "5"
    )
)

GVMD_TENTATIVAS = int(
    os.getenv(
        "GVMD_TENTATIVAS",
        "12"
    )
)

GVMD_ESPERA = int(
    os.getenv(
        "GVMD_ESPERA",
        "10"
    )
)

DIRETORIO_RELATORIOS = Path(
    os.getenv(
        "REPORT_DIR",
        "/relatorios"
    )
)

ARQUIVO_ESTADO = (
    DIRETORIO_RELATORIOS
    / "ultimo_scan.json"
)

ARQUIVO_LOCK = (
    DIRETORIO_RELATORIOS
    / ".automacao_openvas.lock"
)

PORTAS_TESTE_ALVO = [
    80,
    8080
]


# ============================================================
# UTILITÁRIOS
# ============================================================

def agora_iso():
    return datetime.now().isoformat(
        timespec="seconds"
    )


def titulo(texto):
    print("")
    print(
        "=" * 58
    )
    print(
        f" {texto}"
    )
    print(
        "=" * 58
    )


# ============================================================
# BLOQUEIO CONTRA EXECUÇÃO DUPLICADA
# ============================================================

@contextmanager
def adquirir_lock():

    DIRETORIO_RELATORIOS.mkdir(
        parents=True,
        exist_ok=True
    )

    arquivo = ARQUIVO_LOCK.open(
        "w"
    )

    try:

        fcntl.flock(
            arquivo,
            fcntl.LOCK_EX
            | fcntl.LOCK_NB
        )

    except BlockingIOError:

        arquivo.close()

        raise RuntimeError(
            "Já existe outra instância da automação em execução."
        )

    arquivo.write(
        f"pid={os.getpid()}\n"
        f"inicio={agora_iso()}\n"
    )

    arquivo.flush()

    try:
        yield

    finally:

        try:

            fcntl.flock(
                arquivo,
                fcntl.LOCK_UN
            )

        finally:
            arquivo.close()


# ============================================================
# CONEXÃO GMP CURTA
# ============================================================

@contextmanager
def sessao_gmp():

    connection = UnixSocketConnection(
        path=SOCKET_PATH
    )

    transform = (
        EtreeCheckCommandTransform()
    )

    with GMP(
        connection=connection,
        transform=transform
    ) as gmp:

        gmp.authenticate(
            USER,
            PASSWORD
        )

        yield gmp


# ============================================================
# DISPONIBILIDADE DO GVMD
# ============================================================

def aguardar_gvmd_disponivel():

    print(
        "[*] Verificando disponibilidade do gvmd..."
    )

    for tentativa in range(
        1,
        GVMD_TENTATIVAS + 1
    ):

        try:

            with sessao_gmp() as gmp:

                resposta = gmp.get_version()

                versao = resposta.findtext(
                    "version"
                )

                print(
                    "[+] gvmd/GMP disponível."
                )

                if versao:
                    print(
                        f"[+] GMP Version: {versao}"
                    )

                return

        except Exception as erro:

            print(
                f"[!] Tentativa "
                f"{tentativa}/"
                f"{GVMD_TENTATIVAS}: "
                f"{type(erro).__name__}: "
                f"{erro}"
            )

            if (
                tentativa
                < GVMD_TENTATIVAS
            ):
                time.sleep(
                    GVMD_ESPERA
                )

    raise RuntimeError(
        "O gvmd não ficou disponível dentro do tempo limite."
    )


# ============================================================
# TARGET - CONECTIVIDADE
# ============================================================

def validar_conectividade_alvo():

    print("")
    print(
        f"[*] Validando conectividade com {IP_ALVO} ..."
    )

    portas_ok = []

    for porta in PORTAS_TESTE_ALVO:

        try:

            with socket.create_connection(
                (
                    IP_ALVO,
                    porta
                ),
                timeout=3
            ):

                portas_ok.append(
                    porta
                )

                print(
                    f"[+] TCP/{porta}: OK"
                )

        except OSError as erro:

            print(
                f"[!] TCP/{porta}: "
                f"sem resposta "
                f"({erro})"
            )

    if not portas_ok:

        raise RuntimeError(
            f"O alvo {IP_ALVO} não respondeu "
            "em nenhuma das portas de validação. "
            "O scan não será iniciado."
        )

    print(
        "[+] Alvo considerado acessível."
    )


# ============================================================
# OBJETOS GREENBONE
# ============================================================

def localizar_task(gmp):

    resposta = gmp.get_tasks()

    for task in resposta.xpath(
        "task"
    ):

        if (
            task.findtext("name")
            == NOME_TASK
        ):
            return task

    raise RuntimeError(
        f"Task '{NOME_TASK}' "
        "não encontrada."
    )


def localizar_target(
    gmp,
    target_id
):

    resposta = gmp.get_targets()

    for target in resposta.xpath(
        "target"
    ):

        if (
            target.get("id")
            == target_id
        ):
            return target

    raise RuntimeError(
        f"Target ID '{target_id}' "
        "não encontrado."
    )


def consultar_task_por_id(
    gmp,
    task_id
):

    resposta = gmp.get_tasks()

    for task in resposta.xpath(
        "task"
    ):

        if (
            task.get("id")
            == task_id
        ):
            return task

    raise RuntimeError(
        f"Task ID '{task_id}' "
        "não encontrada."
    )


def consultar_task_conexao_curta(
    task_id
):

    with sessao_gmp() as gmp:

        task = consultar_task_por_id(
            gmp,
            task_id
        )

        return {
            "status": task.findtext(
                "status"
            ),
            "progress": task.findtext(
                "progress"
            )
        }


# ============================================================
# PERSISTÊNCIA DO ESTADO
# ============================================================

def salvar_estado(
    task_id,
    report_id,
    status
):

    DIRETORIO_RELATORIOS.mkdir(
        parents=True,
        exist_ok=True
    )

    dados = {
        "task_id": task_id,
        "report_id": report_id,
        "target": IP_ALVO,
        "task": NOME_TASK,
        "status": status,
        "atualizado_em": agora_iso()
    }

    ARQUIVO_ESTADO.write_text(
        json.dumps(
            dados,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def carregar_estado():

    if not ARQUIVO_ESTADO.exists():
        return {}

    try:

        return json.loads(
            ARQUIVO_ESTADO.read_text(
                encoding="utf-8"
            )
        )

    except Exception:
        return {}


# ============================================================
# OBTENÇÃO DO REPORT
# ============================================================

def obter_report(
    gmp,
    report_id
):

    print("")
    print(
        "[*] Obtendo relatório pelo GMP..."
    )

    print(
        f"[*] Report ID: {report_id}"
    )

    try:

        resposta = gmp.get_report(
            report_id=report_id,
            details=True,
            filter_string="rows=-1"
        )

    except TypeError:

        resposta = gmp.get_report(
            report_id=report_id,
            filter_string="rows=-1"
        )

    return resposta


# ============================================================
# PROCESSAMENTO DOS RESULTADOS
# ============================================================

def converter_severidade(
    texto
):

    try:
        return float(
            texto
        )

    except (
        TypeError,
        ValueError
    ):
        return 0.0


def extrair_resultados(
    resposta_report
):

    resultados = []

    for resultado in (
        resposta_report.xpath(
            ".//result"
        )
    ):

        nome = resultado.findtext(
            "name"
        )

        if not nome:

            nome = resultado.findtext(
                "nvt/name"
            )

        host = resultado.findtext(
            "host"
        )

        porta = resultado.findtext(
            "port"
        )

        severity_text = (
            resultado.findtext(
                "severity"
            )
        )

        descricao = (
            resultado.findtext(
                "description"
            )
        )

        severity = (
            converter_severidade(
                severity_text
            )
        )

        resultados.append(
            {
                "nome":
                    nome
                    or "Não informado",

                "host":
                    host
                    or "Não informado",

                "porta":
                    porta
                    or "Não informado",

                "severity":
                    severity,

                "descricao":
                    descricao
                    or ""
            }
        )

    return resultados


def classificar_resultados(
    resultados
):

    criticos = []
    altos = []
    medios = []
    baixos = []
    logs = []

    for resultado in resultados:

        severidade = (
            resultado[
                "severity"
            ]
        )

        if severidade >= 9.0:

            criticos.append(
                resultado
            )

        elif severidade >= 7.0:

            altos.append(
                resultado
            )

        elif severidade >= 4.0:

            medios.append(
                resultado
            )

        elif severidade > 0.0:

            baixos.append(
                resultado
            )

        else:

            logs.append(
                resultado
            )

    return {
        "criticos": criticos,
        "altos": altos,
        "medios": medios,
        "baixos": baixos,
        "logs": logs
    }


# ============================================================
# ARQUIVO XML
# ============================================================

def salvar_xml(
    resposta_report,
    report_id
):

    arquivo = (
        DIRETORIO_RELATORIOS
        / f"report_raw_{report_id}.xml"
    )

    conteudo = etree.tostring(
        resposta_report,
        encoding="utf-8",
        pretty_print=True,
        xml_declaration=True
    )

    arquivo.write_bytes(
        conteudo
    )

    print(
        f"[+] XML bruto salvo em: "
        f"{arquivo}"
    )

    return arquivo


# ============================================================
# ARQUIVO CSV
# ============================================================

def salvar_csv(
    resultados_filtrados,
    report_id
):

    arquivo = (
        DIRETORIO_RELATORIOS
        / (
            "vulnerabilidades_"
            "altas_criticas_"
            f"{report_id}.csv"
        )
    )

    vulnerabilidades = (
        resultados_filtrados[
            "criticos"
        ]
        + resultados_filtrados[
            "altos"
        ]
    )

    with arquivo.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as csvfile:

        writer = csv.writer(
            csvfile,
            delimiter=";"
        )

        writer.writerow(
            [
                "Severidade",
                "Classificação",
                "Host",
                "Porta",
                "Vulnerabilidade"
            ]
        )

        for item in sorted(
            vulnerabilidades,
            key=lambda x: x[
                "severity"
            ],
            reverse=True
        ):

            classificacao = (
                "Crítica"
                if (
                    item["severity"]
                    >= 9.0
                )
                else "Alta"
            )

            writer.writerow(
                [
                    item[
                        "severity"
                    ],
                    classificacao,
                    item[
                        "host"
                    ],
                    item[
                        "porta"
                    ],
                    item[
                        "nome"
                    ]
                ]
            )

    print(
        f"[+] CSV salvo em: "
        f"{arquivo}"
    )

    return arquivo


# ============================================================
# RELATÓRIO TXT
# ============================================================

def salvar_txt(
    resultados_filtrados,
    report_id
):

    timestamp_atual = (
        datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
    )

    arquivo = (
        DIRETORIO_RELATORIOS
        / (
            "relatorio_executivo_"
            "simplificado_"
            f"{timestamp_atual}.txt"
        )
    )

    vulnerabilidades = (
        resultados_filtrados[
            "criticos"
        ]
        + resultados_filtrados[
            "altos"
        ]
    )

    with arquivo.open(
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "====================================================\n"
        )

        f.write(
            "     RELATÓRIO EXECUTIVO SIMPLIFICADO DE RISCOS\n"
        )

        f.write(
            "     Auditoria de Segurança - Ambiente Home-Office\n"
        )

        f.write(
            "     Gerado em: "
            f"{datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}\n"
        )

        f.write(
            "====================================================\n\n"
        )

        f.write(
            f"Target: {NOME_TARGET}\n"
        )

        f.write(
            f"Host analisado: {IP_ALVO}\n"
        )

        f.write(
            f"Task: {NOME_TASK}\n"
        )

        f.write(
            f"Report ID: "
            f"{report_id}\n\n"
        )

        for item in sorted(
            vulnerabilidades,
            key=lambda x: x[
                "severity"
            ],
            reverse=True
        ):

            classificacao = (
                "CRITICAL"
                if (
                    item["severity"]
                    >= 9.0
                )
                else "HIGH"
            )

            f.write(
                "[ALERTA DE RISCO: "
                f"{classificacao}]\n"
            )

            f.write(
                "  - Host Afetado: "
                f"{item['host']}\n"
            )

            f.write(
                "  - Porta/Serviço: "
                f"{item['porta']}\n"
            )

            f.write(
                "  - Vulnerabilidade: "
                f"{item['nome']}\n"
            )

            f.write(
                "  - Severidade CVSS: "
                f"{item['severity']:.1f}\n"
            )

            f.write(
                "-" * 52
                + "\n"
            )

        f.write(
            "\nTotal de vulnerabilidades "
            "críticas e altas identificadas: "
            f"{len(vulnerabilidades)}\n"
        )

    print(
        "[+] Relatório TXT "
        "simplificado salvo em: "
        f"{arquivo}"
    )

    return arquivo


# ============================================================
# RELATÓRIO HTML
# ============================================================

def salvar_relatorio_html(
    resultados,
    classificados,
    report_id
):

    arquivo = (
        DIRETORIO_RELATORIOS
        / (
            "relatorio_executivo_"
            f"{report_id}.html"
        )
    )

    vulnerabilidades_prioritarias = (
        classificados[
            "criticos"
        ]
        + classificados[
            "altos"
        ]
    )

    hosts = {
        item["host"]
        for item in resultados
        if (
            item["host"]
            != "Não informado"
        )
    }

    portas = {
        (
            item["host"],
            item["porta"]
        )
        for item in resultados
        if (
            item["porta"]
            != "Não informado"
        )
    }

    linhas = ""

    for item in sorted(
        vulnerabilidades_prioritarias,
        key=lambda x: x[
            "severity"
        ],
        reverse=True
    ):

        classificacao = (
            "Crítica"
            if (
                item["severity"]
                >= 9
            )
            else "Alta"
        )

        linhas += f"""
        <tr>
            <td>{item["severity"]:.1f}</td>
            <td>{html.escape(classificacao)}</td>
            <td>{html.escape(item["host"])}</td>
            <td>{html.escape(item["porta"])}</td>
            <td>{html.escape(item["nome"])}</td>
        </tr>
        """

    if not linhas:

        linhas = """
        <tr>
            <td colspan="5">
                Nenhuma vulnerabilidade alta ou crítica
                foi retornada neste relatório.
            </td>
        </tr>
        """

    data_geracao = (
        datetime.now().strftime(
            "%d/%m/%Y %H:%M:%S"
        )
    )

    conteudo = f"""<!DOCTYPE html>
<html lang="pt-BR">

<head>
<meta charset="UTF-8">

<title>
Relatório Executivo de Vulnerabilidades
</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    line-height: 1.5;
}}

h1 {{
    text-align: center;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}}

th, td {{
    border: 1px solid #999;
    padding: 8px;
    text-align: left;
}}

.resumo {{
    margin-top: 25px;
}}

</style>
</head>

<body>

<h1>
Relatório Executivo de Vulnerabilidades
</h1>

<p>
<strong>Projeto:</strong>
Sistema Automatizado de Varredura e
Auditoria de Segurança utilizando OpenVAS e Python
</p>

<p>
<strong>Data de geração:</strong>
{data_geracao}
</p>

<p>
<strong>Target:</strong>
{html.escape(NOME_TARGET)}
</p>

<p>
<strong>Endereço analisado:</strong>
{html.escape(IP_ALVO)}
</p>

<p>
<strong>Task:</strong>
{html.escape(NOME_TASK)}
</p>

<p>
<strong>Report ID:</strong>
{html.escape(report_id)}
</p>

<div class="resumo">

<h2>Resumo</h2>

<ul>
    <li>
        Hosts encontrados:
        {len(hosts)}
    </li>

    <li>
        Portas/serviços associados aos resultados:
        {len(portas)}
    </li>

    <li>
        Total de resultados:
        {len(resultados)}
    </li>

    <li>
        Críticos:
        {len(classificados["criticos"])}
    </li>

    <li>
        Altos:
        {len(classificados["altos"])}
    </li>

    <li>
        Médios:
        {len(classificados["medios"])}
    </li>

    <li>
        Baixos:
        {len(classificados["baixos"])}
    </li>

    <li>
        Informativos/Log:
        {len(classificados["logs"])}
    </li>
</ul>

</div>

<h2>
Vulnerabilidades priorizadas
</h2>

<p>
Nesta seção são apresentados somente resultados
com severidade igual ou superior a 7.0.
</p>

<table>

<thead>
<tr>
    <th>Severidade</th>
    <th>Classificação</th>
    <th>Host</th>
    <th>Porta</th>
    <th>Vulnerabilidade</th>
</tr>
</thead>

<tbody>
{linhas}
</tbody>

</table>

</body>
</html>
"""

    arquivo.write_text(
        conteudo,
        encoding="utf-8"
    )

    print(
        "[+] Relatório executivo "
        f"salvo em: {arquivo}"
    )

    return arquivo


# ============================================================
# PROCESSAMENTO DO REPORT
# ============================================================

def processar_report(
    gmp,
    report_id
):

    resposta_report = obter_report(
        gmp,
        report_id
    )

    resultados = extrair_resultados(
        resposta_report
    )

    classificados = (
        classificar_resultados(
            resultados
        )
    )

    titulo(
        "RESULTADOS DO RELATÓRIO"
    )

    print(
        "Total de resultados: "
        f"{len(resultados)}"
    )

    print(
        "Críticos: "
        f"{len(classificados['criticos'])}"
    )

    print(
        "Altos: "
        f"{len(classificados['altos'])}"
    )

    print(
        "Médios: "
        f"{len(classificados['medios'])}"
    )

    print(
        "Baixos: "
        f"{len(classificados['baixos'])}"
    )

    print(
        "Log/Informativos: "
        f"{len(classificados['logs'])}"
    )

    print("")
    print(
        "[*] Gerando arquivos "
        "do relatório..."
    )

    DIRETORIO_RELATORIOS.mkdir(
        parents=True,
        exist_ok=True
    )

    arquivo_xml = salvar_xml(
        resposta_report,
        report_id
    )

    arquivo_csv = salvar_csv(
        classificados,
        report_id
    )

    arquivo_txt = salvar_txt(
        classificados,
        report_id
    )

    arquivo_html = (
        salvar_relatorio_html(
            resultados,
            classificados,
            report_id
        )
    )

    titulo(
        "RELATÓRIO GERADO"
    )

    return {
        "resultados":
            resultados,

        "classificados":
            classificados,

        "arquivos": {
            "xml":
                str(
                    arquivo_xml
                ),

            "csv":
                str(
                    arquivo_csv
                ),

            "txt":
                str(
                    arquivo_txt
                ),

            "html":
                str(
                    arquivo_html
                )
        }
    }


# ============================================================
# PROCESSAMENTO COM RETRY
# ============================================================

def processar_report_com_retry(
    report_id
):

    falhas = 0

    while True:

        try:

            print("")
            print(
                "[*] Abrindo conexão GMP "
                "para processamento "
                "do relatório..."
            )

            with sessao_gmp() as gmp:

                return processar_report(
                    gmp,
                    report_id
                )

        except (
            TimeoutError,
            ConnectionError,
            OSError,
            GvmError
        ) as erro:

            falhas += 1

            print(
                "[!] Falha GMP no "
                "processamento "
                f"({falhas}/"
                f"{MAX_FALHAS_PROCESSAMENTO}): "
                f"{type(erro).__name__}: "
                f"{erro}"
            )

            if (
                falhas
                >= MAX_FALHAS_PROCESSAMENTO
            ):

                raise RuntimeError(
                    "Não foi possível recuperar "
                    "o relatório após várias "
                    "tentativas. "
                    "Report ID preservado: "
                    f"{report_id}"
                ) from erro

            print(
                "[*] Nova tentativa "
                "em 20 segundos..."
            )

            time.sleep(
                20
            )


# ============================================================
# MONITORAMENTO
# ============================================================

def monitorar_varredura(
    task_id,
    report_id
):

    titulo(
        "MONITORAMENTO"
    )

    print(
        "[*] Cada consulta utilizará "
        "uma nova conexão GMP."
    )

    falhas_consecutivas = 0

    while True:

        try:

            estado = (
                consultar_task_conexao_curta(
                    task_id
                )
            )

            falhas_consecutivas = 0

            status_atual = (
                estado[
                    "status"
                ]
            )

            progresso = (
                estado[
                    "progress"
                ]
            )

            agora = (
                datetime.now().strftime(
                    "%H:%M:%S"
                )
            )

            print(
                f"[{agora}] "
                f"Status: "
                f"{status_atual} | "
                f"Progresso: "
                f"{progresso}"
            )

            salvar_estado(
                task_id,
                report_id,
                status_atual
            )

            status_lower = (
                status_atual
                .strip()
                .lower()
                if status_atual
                else ""
            )

            if (
                status_lower
                == "done"
            ):

                print(
                    "[+] Varredura concluída."
                )

                return

            if status_lower in [
                "stopped",
                "interrupted",
                "error"
            ]:

                raise RuntimeError(
                    "Varredura terminou "
                    f"em estado "
                    f"'{status_atual}'. "
                    "Report ID: "
                    f"{report_id}"
                )

        except (
            TimeoutError,
            ConnectionError,
            OSError,
            GvmError
        ) as erro:

            falhas_consecutivas += 1

            agora = (
                datetime.now().strftime(
                    "%H:%M:%S"
                )
            )

            print(
                f"[{agora}] "
                "[!] Falha temporária GMP "
                f"({falhas_consecutivas}/"
                f"{MAX_FALHAS_MONITORAMENTO})"
            )

            print(
                "    "
                f"{type(erro).__name__}: "
                f"{erro}"
            )

            print(
                "    Report ID preservado: "
                f"{report_id}"
            )

            if (
                falhas_consecutivas
                >= MAX_FALHAS_MONITORAMENTO
            ):

                raise RuntimeError(
                    "Monitoramento GMP "
                    "indisponível após várias "
                    "tentativas. "
                    "O scan pode continuar "
                    "no Greenbone. "
                    "Report ID: "
                    f"{report_id}"
                ) from erro

        time.sleep(
            INTERVALO_MONITORAMENTO
        )


# ============================================================
# MAIN
# ============================================================

def main():

    if not PASSWORD:

        raise RuntimeError(
            "A variável GVM_PASSWORD "
            "não foi definida."
        )

    titulo(
        "AUTOMAÇÃO OPENVAS + PYTHON"
    )

    print(
        f"[*] Target esperado: "
        f"{NOME_TARGET}"
    )

    print(
        f"[*] Endereço esperado: "
        f"{IP_ALVO}"
    )

    print(
        f"[*] Task esperada: "
        f"{NOME_TASK}"
    )

    print(
        "[*] Modo: "
        + (
            "NOVA VARREDURA"
            if START_SCAN
            else "PROCESSAR RELATÓRIO"
        )
    )

    aguardar_gvmd_disponivel()

    # ========================================================
    # CONSULTA INICIAL
    # ========================================================

    print("")
    print(
        "[*] Validando Task "
        "e Target..."
    )

    with sessao_gmp() as gmp:

        task = localizar_task(
            gmp
        )

        task_id = task.get(
            "id"
        )

        status = task.findtext(
            "status"
        )

        progresso = task.findtext(
            "progress"
        )

        print(
            f"[+] Task ID: "
            f"{task_id}"
        )

        print(
            f"[+] Status atual: "
            f"{status}"
        )

        print(
            f"[+] Progresso atual: "
            f"{progresso}"
        )

        target_ref = task.find(
            "target"
        )

        if target_ref is None:

            raise RuntimeError(
                "A Task não possui "
                "Target associado."
            )

        target_id = (
            target_ref.get(
                "id"
            )
        )

        target = localizar_target(
            gmp,
            target_id
        )

        hosts = (
            target.findtext(
                "hosts"
            )
            or ""
        ).strip()

        print(
            f"[+] Target ID: "
            f"{target_id}"
        )

        print(
            f"[+] Host configurado: "
            f"{hosts}"
        )

        if (
            hosts
            != IP_ALVO
        ):

            raise RuntimeError(
                "Target aponta para "
                f"'{hosts}' em vez de "
                f"'{IP_ALVO}'."
            )

        # ====================================================
        # NOVA VARREDURA
        # ====================================================

        if START_SCAN:

            status_normalizado = (
                status.strip().lower()
                if status
                else ""
            )

            # Proteção adicional.
            if status_normalizado in [
                "requested",
                "queued",
                "running"
            ]:

                print("")
                print(
                    "[!] Já existe uma "
                    "varredura em execução."
                )

                print(
                    "[*] Nova execução "
                    "não será iniciada."
                )

                return 0

            permitidos = [
                "new",
                "done",
                "stopped",
                "interrupted"
            ]

            if (
                status_normalizado
                not in permitidos
            ):

                raise RuntimeError(
                    "A Task não pode "
                    "ser iniciada no "
                    f"estado '{status}'."
                )

            validar_conectividade_alvo()

            titulo(
                "INICIANDO NOVA VARREDURA"
            )

            resposta_start = (
                gmp.start_task(
                    task_id=task_id
                )
            )

            report_id = (
                resposta_start.findtext(
                    ".//report_id"
                )
            )

            if not report_id:

                raise RuntimeError(
                    "start_task() não "
                    "retornou Report ID."
                )

            print(
                f"[+] Report ID: "
                f"{report_id}"
            )

            salvar_estado(
                task_id,
                report_id,
                "Requested"
            )

        # ====================================================
        # REPORT EXISTENTE
        # ====================================================

        else:

            report_id = (
                REPORT_ID_EXISTENTE
            )

            if not report_id:

                estado_salvo = (
                    carregar_estado()
                )

                report_id = (
                    estado_salvo.get(
                        "report_id"
                    )
                )

                if report_id:

                    print(
                        "[*] REPORT_ID não "
                        "informado."
                    )

                    print(
                        "[*] Utilizando último "
                        "Report ID salvo: "
                        f"{report_id}"
                    )

            if not report_id:

                raise RuntimeError(
                    "START_SCAN=0 exige "
                    "REPORT_ID ou um "
                    "ultimo_scan.json válido."
                )

            print(
                "[*] Relatório selecionado: "
                f"{report_id}"
            )

    # A sessão GMP inicial foi encerrada neste ponto.

    # ========================================================
    # MONITORAMENTO
    # ========================================================

    if START_SCAN:

        monitorar_varredura(
            task_id,
            report_id
        )

    # ========================================================
    # PROCESSAMENTO FINAL
    # ========================================================

    titulo(
        "PROCESSAMENTO FINAL"
    )

    resumo = (
        processar_report_com_retry(
            report_id
        )
    )

    salvar_estado(
        task_id,
        report_id,
        "Processado"
    )

    titulo(
        "AUTOMAÇÃO CONCLUÍDA"
    )

    print(
        f"Task ID:   "
        f"{task_id}"
    )

    print(
        f"Target:    "
        f"{IP_ALVO}"
    )

    print(
        f"Report ID: "
        f"{report_id}"
    )

    print("")

    print(
        "[+] Fluxo concluído "
        "com sucesso."
    )

    print("")
    print(
        "[+] Arquivos:"
    )

    for tipo, caminho in (
        resumo[
            "arquivos"
        ].items()
    ):

        print(
            f"    {tipo.upper()}: "
            f"{caminho}"
        )

    return 0


# ============================================================
# EXECUÇÃO
# ============================================================

if __name__ == "__main__":

    try:

        with adquirir_lock():

            codigo = main()

            sys.exit(
                codigo
                if codigo is not None
                else 0
            )

    except KeyboardInterrupt:

        print("")
        print(
            "[-] Execução interrompida "
            "pelo usuário."
        )

        sys.exit(130)

    except Exception as erro:

        print("")

        titulo(
            "ERRO"
        )

        print(
            f"[-] "
            f"{type(erro).__name__}: "
            f"{erro}"
        )

        sys.exit(1)