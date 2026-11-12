FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
COPY src ./src
ENV HOST=0.0.0.0
EXPOSE 3000
USER node
CMD ["node", "src/server.js"]
