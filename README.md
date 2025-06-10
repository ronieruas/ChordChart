Projeto "ChordChart Pro" 3.0- Guia de Implantação
Este guia detalha a estrutura do projeto e como implantá-lo como um serviço web usando Docker em um servidor (como uma VM Proxmox).
Essa Atualização
Backend Fortalecido: Utilizei a biblioteca Flask-Login para gerenciar sessões de usuário de forma segura. Todas as rotas da API que lidam com músicas (/api/songs/...) agora exigem que o usuário esteja logado.
Banco de Dados de Usuários: Criei uma nova tabela no banco de dados para armazenar nomes de usuário e senhas criptografadas (usando werkzeug para hashing, a prática recomendada).
Frontend com Tela de Login: A aplicação agora verifica se o usuário está logado. Se não estiver, ela exibe uma tela de login em vez do painel principal.
Criação de Usuário Segura: Para evitar senhas padrão, adicionei um script que você executa uma vez para criar seu primeiro usuário administrador de forma segura.
Logout: Adicionei um botão de "Sair" na interface.
A seguir, apresento a nova estrutura e o código atualizado.

Estrutura dos Arquivos
Para manter o projeto organizado no GitHub, use a seguinte estrutura.

//chordchart-pro/
|-- docker-compose.yml       # ATUALIZADO
|-- nginx.conf               # (Sem alterações)
|-- .env                     # NOVO: Para variáveis de ambiente seguras
|
|-- /app/
|   |-- index.html           # ATUALIZADO
|
|-- /backend/
|   |-- Dockerfile           # (Sem alterações)
|   |-- app.py               # ATUALIZADO
|   |-- requirements.txt     # ATUALIZADO
|   |-- create_user.py       # NOVO: Script para criar o primeiro usuário
|
|-- README.md               # Este arquivo

Conteúdo dos Arquivos de Configuração
Copie e cole o conteúdo abaixo nos arquivos correspondentes.


Clone seu Projeto do GitHub: Após fazer o login novamente, clone o repositório que você criou.

# Instale o git se ainda não tiver
sudo apt install git -y

# Clone seu repositório
git clone https://github.com/SEU_USUARIO/chordchart-pro.git

# Entre no diretório do projeto
cd chordchart-pro

Inicie a Aplicação: Dentro do diretório principal do projeto (onde está o docker-compose.yml), execute o comando:

docker-compose up -d

O -d (detached) faz com que o container rode em segundo plano.

Acesse a Aplicação: Pronto! Agora você pode acessar sua ferramenta no navegador usando o IP da sua VM Proxmox e a porta que você mapeou (8080).
http://IP_DA_SUA_VM:8080