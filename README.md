# SSH Manager

Gerenciador local de servidores SSH em linha de comando, com cadastro, edição,
remoção, busca, **agrupamento**, **porta personalizada**, **exportação** e
**importação**.

As senhas **não são gravadas em texto puro**: são cifradas com
[Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256)
antes de serem salvas. Exportações com senhas usam uma chave derivada por
**scrypt** a partir de uma senha informada por você.

## Recursos

- CRUD completo com validação de nome, grupo, DNS, IP, porta, usuário e chave.
- Agrupamento de hosts, com filtro e sugestão de grupos existentes.
- Porta SSH por servidor (padrão 22), usada no comando e na sessão.
- Busca por nome, grupo, host, porta, usuário, descrição ou chave.
- Detalhes com senhas mascaradas e revelação opcional.
- Cópia do comando SSH para a área de transferência.
- Abertura de sessão SSH com chave e porta.
- Exportação JSON (com ou sem senhas) e CSV.
- Importação com mesclagem por nome (ignorar ou sobrescrever).

## Requisitos

- Python **3.11+**
- Dependência: `cryptography` (versão fixada em `requirements.txt`)
- Cliente SSH no PATH (opcional, apenas para "Abrir sessão SSH")

## Instalação

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Uso

```powershell
python ssh_manager.py
# equivalente:
python -m sshmanager
```

Menu principal:

```
1  Listar servidores
2  Cadastrar servidor
3  Editar servidor
4  Remover servidor
5  Buscar
6  Ver detalhes
7  Copiar comando SSH
8  Abrir sessão SSH
9  Listar por grupo
10 Exportar servidores
11 Importar servidores
0  Sair
```

A seleção de servidor aceita o **número** da tabela ou o **nome** (inclusive
trecho do nome, quando não houver ambiguidade).

### Cadastro

Campos solicitados, na ordem:

| Campo | Obrigatório | Observação |
|---|---|---|
| Nome | sim | único (sem diferenciar maiúsculas/minúsculas) |
| Grupo | não | até 40 caracteres; grupos existentes são sugeridos |
| DNS | não* | hostname; usado preferencialmente na conexão |
| IP | não* | IPv4 ou IPv6; validado com `ipaddress` |
| Porta SSH | não | 1 a 65535; padrão 22 |
| Usuário SSH | sim | sem espaços, não pode começar com `-` |
| Senha do usuário | não | digitada oculta, com confirmação |
| Usuário root | sim | padrão `root` |
| Senha do root | não | digitada oculta, com confirmação |
| Descrição | não | até 200 caracteres |
| Chave SSH | não | caminho do arquivo privado; `~` é expandido |

\* É obrigatório informar **ao menos DNS ou IP**.

### Grupos

O grupo é um rótulo livre (ex.: `Produção`, `Homologação`, `Clientes`). A
comparação ignora maiúsculas/minúsculas, e o programa reaproveita a grafia de
um grupo já existente.

- Na edição, `-` remove o grupo.
- A opção **9** lista apenas os hosts de um grupo (ou os sem grupo, com `-`).
- A exportação também pode ser limitada a um grupo.

### Porta personalizada

Cada servidor tem sua porta (padrão 22). Ela aparece na listagem, nos detalhes
e no comando gerado:

```text
ssh -p 2222 -i "C:\Users\jonat\.ssh\id_ed25519" deploy@web01.example.com
```

Quando a porta é 22, o `-p` é omitido para manter o comando limpo. A opção
"Abrir sessão SSH" usa a mesma porta.

### Edição

Enter mantém o valor atual. Para campos opcionais, `-` limpa o valor. Para
senhas, o menu oferece `[Enter] manter`, `[n] nova` e `[-] remover`.

### Modo não interativo

```powershell
python ssh_manager.py --list
```

Útil para scripts e inventário rápido. Também há `--version` e `--help`.

## Exportação

Menu **10**. Escolha o escopo (todos ou um grupo) e o formato:

| Formato | Senhas | Uso indicado |
|---|---|---|
| JSON sem senhas (padrão) | não | Compartilhar inventário, versionar, migrar |
| JSON com senhas | sim, protegidas por senha | Backup completo ou migração entre máquinas |
| CSV | não | Planilhas (Excel/LibreOffice) |

- O JSON com senhas usa **scrypt** (N=2¹⁵, r=8, p=1) para derivar a chave e
  **Fernet** para cifrar o conteúdo. A senha precisa ter ao menos 8 caracteres.
- O CSV é gravado em UTF-8 com BOM (`utf-8-sig`) para preservar acentos no
  Excel e **nunca** inclui senhas.
- O arquivo é gravado de forma atômica. Se o destino já existir, é pedida
  confirmação.
- Por padrão, o nome do arquivo é `ssh-servers-AAAAMMDD-HHMMSS.json|csv` no
  diretório atual.

> **Guarde a senha da exportação.** Sem ela, as senhas do JSON cifrado são
> irrecuperáveis. O arquivo cifrado também deve ser tratado como confidencial.

## Importação

Menu **11**. Formatos aceitos:

- JSON gerado por este programa (com ou sem senha).
- CSV com cabeçalho.
- JSON simples: uma lista de objetos ou `{"servers": [...]}`.

Ao encontrar um servidor com o mesmo nome, escolha:

```
1  Ignorar (manter o existente)      ← padrão
2  Sobrescrever (usar o arquivo)
0  Cancelar
```

Regras importantes:

- Se o arquivo **não** tiver senhas (JSON sem senhas ou CSV), as senhas já
  existentes são **preservadas** na sobrescrita. Servidores novos entram sem
  senha e podem ser editados depois.
- Registros inválidos são ignorados e listados ao final; os válidos são
  importados.
- Tudo é gravado em uma única operação atômica ao final.
- O arquivo interno `servers.json` **não** deve ser importado diretamente
  (as senhas estão cifradas com a chave local). Use **Exportar**.
- Cabeçalhos em português são aceitos na importação: `nome`, `grupo`, `porta`,
  `usuário`, `senha`, `senha root`, `descrição`, `chave ssh`, etc.

## Onde ficam os dados

Por padrão:

- Windows: `%APPDATA%\SSHManager\`
- Linux/macOS: `~/.config/ssh-manager/`

Arquivos:

- `servers.json` — cadastro com senhas cifradas (schema **2**)
- `secret.key` — chave Fernet usada para cifrar/decifrar
- `servers.json.bak` — backup automático da versão anterior

Arquivos no formato antigo (schema 1) são carregados automaticamente com
`grupo = ""` e `porta = 22`; a próxima gravação atualiza o schema.

Para usar outro diretório:

```powershell
python ssh_manager.py --data-dir D:\dados\ssh
# ou
$env:SSH_MANAGER_HOME = "D:\dados\ssh"
```

## Segurança

- **Senhas cifradas em repouso.** O JSON contém tokens Fernet; os testes
  garantem que as senhas em texto puro não aparecem no arquivo.
- **Chave separada.** `secret.key` é criado com permissões restritas
  (`icacls` no Windows, `chmod 600` em Linux/macOS) e nunca é versionado.
- **Exportações seguras.** Sem senhas por padrão; com senhas, somente por
  scrypt + Fernet e com senha de proteção.
- **Sem senha em linha de comando.** A opção "Abrir sessão SSH" não passa a
  senha como argumento (evita exposição em histórico/lista de processos); o
  `ssh` solicita a senha ou usa a chave.
- **Gravação atômica.** Arquivo temporário + `os.replace`, com backup `.bak`
  e recuperação automática se o JSON estiver corrompido.
- **Entrada oculta.** Senhas são lidas com `getpass`, sem eco no terminal.
- **Limites de KDF na importação.** Parâmetros de scrypt são validados para
  evitar consumo excessivo de memória com arquivos maliciosos.

### Limitações importantes

- Quem tiver acesso aos **dois arquivos** (`servers.json` e `secret.key`) e à
  sua sessão do Windows consegue decifrar as senhas. Proteja sua conta e o
  disco (BitLocker é recomendado).
- **Não** sincronize esse diretório em repositórios públicos ou nuvens sem
  criptografia adicional.
- Se `secret.key` for perdido, as senhas são irrecuperáveis. Faça backup dos
  dois arquivos **juntos**.
- Este programa é um inventário local; não substitui um cofre de senhas
  corporativo (Vault, 1Password, etc.).

## Testes

```powershell
python -m unittest discover -s tests -v
```

43 testes cobrem validação (incluindo grupo e porta), cifragem/decifragem,
CRUD, persistência, migração de schema, recuperação de backup, exportação
JSON/CSV, exportação cifrada, senha incorreta, limites de KDF, normalização de
cabeçalhos e mesclagem de importação.

Qualidade de código (opcional):

```powershell
python -m pip install ruff
ruff check .
ruff format --check .
```

## Estrutura

```
ssh_manager.py              # ponto de entrada (wrapper fino)
sshmanager/
  __init__.py               # API pública do pacote
  __main__.py               # permite python -m sshmanager
  config.py                 # constantes, schema e formato de exportação
  errors.py                 # AppError e subclasses
  utils.py                  # diretórios, permissões e gravação atômica
  crypto.py                 # Fernet (repouso) e scrypt/Fernet (exportação)
  models.py                 # Server, parse_port e validações
  repository.py             # persistência em servers.json
  prompts.py                # leitura/validação de entrada no terminal
  presentation.py           # tabelas, comando SSH e área de transferência
  transfer.py               # exportação/importação (núcleo sem prompts)
  cli.py                    # menus, SSHManagerApp, argparse e main
tests/test_ssh_manager.py   # testes automatizados
requirements.txt            # dependências fixadas
README.md
.gitignore
```

A separação segue uma direção única de dependências: `models` e `crypto`
não conhecem a CLI; `transfer` não faz prompts; `cli` apenas orquestra as
camadas. Assim, regras de validação e formatos de arquivo ficam em um único
lugar, testável sem interação.

## Exemplo de sessão

```
1  Listar servidores
...
Escolha uma opção: 1

+-----+------------------+--------------+--------------------------+-------+------------+----------------------+
| #   | Nome             | Grupo        | Host                     | Porta | Usuário    | Descrição            |
+-----+------------------+--------------+--------------------------+-------+------------+----------------------+
| 1   | Web 01           | Produção     | web01.example.com        | 2222  | deploy     | Aplicação            |
| 2   | Homolog 01       | Homologação  | 10.0.0.20                | 22    | admin      | Testes               |
+-----+------------------+--------------+--------------------------+-------+------------+----------------------+

Escolha uma opção: 7

Número ou nome do servidor (Enter cancela): 1

  Comando: ssh -p 2222 -i "C:\Users\jonat\.ssh\id_ed25519" deploy@web01.example.com
  Comando copiado para a área de transferência.
```
