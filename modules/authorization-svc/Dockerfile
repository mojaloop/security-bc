FROM node:16.13-alpine as builder

# Create app directory
WORKDIR /app

# build requirements
RUN apk --no-cache add git
RUN apk add --no-cache -t build-dependencies make gcc g++ python3 libtool libressl-dev openssl-dev autoconf automake \
    && cd $(npm root -g)/npm \
    && npm config set unsafe-perm true \
    && npm install -g node-gyp

# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

# If you are building your code for production
#RUN npm ci --only=production
RUN npm install

# Bundle app source
COPY tsconfig.json ./
COPY src ./src

# build
RUN npm run build


FROM node:16.13-alpine
WORKDIR /app

COPY --from=builder /app .

# kafka handler, no http server yet
EXPOSE 3202

CMD [ "node", "dist/application/index.js" ]
