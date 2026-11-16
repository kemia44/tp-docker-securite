FROM node:18-alpine

WORKDIR /app

COPY package.json package-lock.json ./
COPY .. ./

RUN npm install


RUN npm install -g serve
RUN npm run build
RUN rm -fr node_modules

EXPOSE 3000

CMD ["serve", "-s", "dist"]
