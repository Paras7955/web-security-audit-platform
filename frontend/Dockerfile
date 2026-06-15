FROM node:22-alpine

WORKDIR /app/frontend

COPY frontend/package.json ./
RUN npm install

COPY frontend/ .
COPY shared/ /app/shared/

EXPOSE 3000

CMD ["npm", "run", "dev"]
