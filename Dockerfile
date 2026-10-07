FROM node:20-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server procps curl git nano python3 htop ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
RUN chmod +x start.sh && sed -i 's/\r$//' start.sh sshd_config
ENV NODE_ENV=production
CMD ["./start.sh"]
