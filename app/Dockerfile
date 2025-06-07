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