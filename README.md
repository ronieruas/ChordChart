Projeto "ChordChart Pro" - Guia de Implantação
Este guia detalha a estrutura do projeto e como implantá-lo como um serviço web usando Docker em um servidor (como uma VM Proxmox).

Estrutura dos Arquivos
Para manter o projeto organizado no GitHub, use a seguinte estrutura. O nosso projeto será autocontido em um único arquivo index.html por simplicidade, mas essa estrutura permite expandi-lo facilmente no futuro.

/chordchart-pro/
|-- docker-compose.yml       # Orquestra o nosso serviço web
|-- /app/
|   |-- Dockerfile           # Define a imagem do nosso container web
|   |-- index.html           # O arquivo da nossa aplicação (fornecido abaixo)
|   |-- nginx.conf           # Configuração básica do servidor Nginx
|
|-- README.md                # Este arquivo

Conteúdo dos Arquivos de Configuração
Copie e cole o conteúdo abaixo nos arquivos correspondentes.

1. docker-compose.yml
Este arquivo define o serviço da nossa aplicação, mapeando a porta 8080 do host para a porta 80 do container.

version: '3.8'

services:
  web:
    build:
      context: ./app
    container_name: chordchart_pro_web
    ports:
      - "8080:80"
    restart: unless-stopped
    volumes:
      - ./app:/usr/share/nginx/html:ro # Monta o diretório da app como somente leitura

2. app/Dockerfile
Este arquivo cria a imagem Docker. Ele usa uma imagem leve do servidor web Nginx e copia nossa aplicação para dentro dela.

# Usar a imagem oficial do Nginx
FROM nginx:alpine

# Remover a configuração padrão do Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copiar a nossa configuração personalizada do Nginx
COPY nginx.conf /etc/nginx/conf.d/

# Copiar os arquivos da aplicação para o diretório web do Nginx
COPY . /usr/share/nginx/html

# Expor a porta 80 para tráfego web
EXPOSE 80

# O comando padrão do Nginx (`nginx -g 'daemon off;'`) será executado quando o container iniciar.

3. app/nginx.conf
Configuração mínima para o Nginx servir nosso arquivo index.html.

server {
    listen       80;
    server_name  localhost;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
        try_files $uri $uri/ /index.html; # Essencial para futuras rotas de front-end
    }

    # Redirecionar logs de erro e acesso para o Docker
    error_log  /dev/stderr;
    access_log /dev/stdout;
}

Passos para Implantação na VM Proxmox
Prepare a VM: Crie uma VM Linux (Debian ou Ubuntu são ótimas opções) no seu Proxmox. Acesse-a via SSH.

Instale o Docker e o Docker Compose:

# Atualizar pacotes
sudo apt update && sudo apt upgrade -y

# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Instalar Docker Compose
sudo apt install docker-compose -y

# Adicionar seu usuário ao grupo do Docker (evita usar `sudo` para cada comando docker)
sudo usermod -aG docker $USER

# Faça logout e login novamente para que a mudança de grupo tenha efeito
exit

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