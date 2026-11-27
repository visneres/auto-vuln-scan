# OpenVAS / Greenbone Community Edition — Lab FATEC

Guia de referência operacional e documentação do ambiente de laboratório virtualizado utilizado no projeto de varredura e auditoria de vulnerabilidades.

---

## Ambiente

| Componente | Especificação |
| :--- | :--- |
| **Sistema Operacional** | Ubuntu Server 26.04.1 LTS |
| **Hostname** | `openVAS` |
| **Plataforma** | VirtualBox |
| **Greenbone / OpenVAS** | Docker Compose |
| **Diretório do Projeto** | `/home/open/greenbone-community-edition` |

---

## 1. Acesso à Máquina Virtual via SSH

* **Usuário:** `open`
* **Senha:** `123`
* **IP NAT atual da VM:** `10.0.2.15`

**Acesso pelo PowerShell do Windows:**

```powershell
ssh open@127.0.0.1 -p 2222
```

**Port Forward configurado no VirtualBox:**

| Host | Porta Host | Porta Guest |
| :--- | :--- | :--- |
| `127.0.0.1` | `2222` | `22` |

---

## 2. Acesso ao Dashboard do OpenVAS

* **Usuário:** `admin`
* **Senha:** `fatec`

Como o Greenbone está publicado somente no `localhost` da VM, é necessário criar um túnel SSH para acessar a interface pelo navegador do Windows.

1. Abra um **PowerShell separado** e execute:

```powershell
ssh -L 8443:127.0.0.1:443 open@127.0.0.1 -p 2222
```

2. Informe a senha SSH (`123`).

> **Importante:** Deixe essa janela do PowerShell aberta enquanto estiver utilizando o dashboard.

3. Acesse no navegador:
   * **URL:** `https://127.0.0.1:8443`
   * **Usuário:** `admin`
   * **Senha:** `fatec`

> **Observação:** O navegador poderá apresentar um aviso de segurança referente ao certificado HTTPS. Isso ocorre porque o ambiente utiliza certificado TLS autoassinado e é esperado neste laboratório.

---

## 3. Diretório do Greenbone

Após acessar a VM via SSH, navegue até o diretório da stack:

```bash
cd ~/greenbone-community-edition
```

Ou pelo caminho absoluto:

```bash
cd /home/open/greenbone-community-edition
```

---

## 4. Verificar Status dos Containers

Ver serviços ativos:

```bash
docker compose ps
```

Ver todos os serviços, inclusive os finalizados:

```bash
docker compose ps -a
```

Ver somente os principais serviços:

```bash
docker compose ps -a | grep -E 'gvmd|ospd-openvas|openvasd|gsad|nginx|scap-data|vulnerability-tests|notus-data|pg-gvm'
```

---

## 5. Iniciar o OpenVAS

Entrar no diretório e iniciar os containers em segundo plano:

```bash
cd ~/greenbone-community-edition
docker compose up -d
```

Aguardar a inicialização e verificar o status:

```bash
docker compose ps -a
```

---

## 6. Parar o Ambiente

Para parar os containers **sem excluir os dados**:

```bash
cd ~/greenbone-community-edition
docker compose stop
```

Para iniciar novamente:

```bash
docker compose start
```

> **Atenção:** Evite utilizar `docker compose down -v`, pois a opção `-v` remove os volumes e pode apagar dados e feeds armazenados.

---

## 7. Ver Logs

Logs gerais (últimas 100 linhas):

```bash
docker compose logs --tail=100
```

Acompanhar logs em tempo real (pressione `CTRL + C` para sair):

```bash
docker compose logs -f
```

Logs específicos de serviços:

```bash
# Logs do GVMD
docker compose logs --tail=100 gvmd

# Logs do scanner OpenVAS
docker compose logs --tail=100 ospd-openvas
```

---

## 8. Verificar Recursos da VM

Comandos de monitoramento do sistema e dos containers:

```bash
# Memória RAM e Swap
free -h

# Quantidade de vCPUs
nproc

# Espaço em disco
df -h /

# Consumo dos containers
docker stats --no-stream
```

**Configuração atual aproximada:**
* **RAM da VM:** 4 GB
* **CPU:** 2 vCPU
* **Swap:** 6 GB
* **Disco:** ~60 GB

---

## 9. Feeds do OpenVAS

Após acessar o Dashboard, navegue até:

`Administration` $\rightarrow$ `Feed Status`

Os principais feeds devem aparecer com o status **`Current`**:

| Feed | Status Esperado |
| :--- | :--- |
| `NVT` | `Current` |
| `SCAP` | `Current` |
| `CERT` | `Current` |
| `GVMD_DATA` | `Current` |

> Caso apareça `"Update in progress"` ou mensagem de sincronização, aguarde a conclusão antes de executar novas varreduras.

---

## 10. Arquitetura Resumida

### Infraestrutura e Serviços

```text
Windows 11
    │
    │ SSH - Porta 2222
    ▼
Ubuntu Server / openVAS
    │
    └── Docker
         │
         └── Greenbone Community Edition
              ├── GVMD
              ├── OpenVAS
              ├── OSPD-OpenVAS
              ├── PostgreSQL
              ├── Redis
              ├── GSA
              ├── GSAD
              ├── Nginx
              └── Feeds NVT / SCAP / CERT
```

### Fluxo de Acesso ao Dashboard

```text
Windows (127.0.0.1:8443)
    │
    │ Túnel SSH
    ▼
Ubuntu VM (127.0.0.1:443)
    │
    └── Greenbone / OpenVAS
```

---

## 11. Comandos Rápidos

| Ação | Comando / Endereço |
| :--- | :--- |
| **SSH na VM** | `ssh open@127.0.0.1 -p 2222` |
| **Túnel para Dashboard** | `ssh -L 8443:127.0.0.1:443 open@127.0.0.1 -p 2222` |
| **URL do Dashboard** | `https://127.0.0.1:8443` |
| **Iniciar Greenbone** | `cd ~/greenbone-community-edition && docker compose up -d` |
| **Ver status** | `docker compose ps -a` |
| **Parar serviços** | `docker compose stop` |

---

## 12. Credenciais do Laboratório

| Serviço | Usuário | Senha |
| :--- | :--- | :--- |
| **VM Ubuntu / SSH** | `open` | `123` |
| **OpenVAS / Greenbone Dashboard** | `admin` | `fatec` |

---

## Aviso

> Este ambiente é destinado exclusivamente a **laboratório, estudo e testes autorizados**.  
> As credenciais acima são credenciais de laboratório e **não devem ser reutilizadas** em ambientes reais ou de produção.