FROM node:18.13-alpine as builder

# Create app directory
WORKDIR /app

# build requirements
RUN apk --no-cache add git
RUN apk add --no-cache -t build-dependencies bash make gcc g++ python3 libtool lz4-dev librdkafka openssl-dev autoconf automake \
    && cd $(npm root -g)/npm \
    && npm config set unsafe-perm true \
    && npm install -g node-gyp

# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

# If you are building your code for production
#RUN npm ci --only=production
RUN npm install

# Bundle tsconfig.json from the root of the monorepo (per package files use extends)
COPY ../../tsconfig.json ./
CMD ls -la

# Bundle app source
COPY src ./src
CMD ls -la
# build
RUN npm run build


FROM node:18.13-alpine
WORKDIR /app

COPY --from=builder /app .

# kafka handler, no http server yet
EXPOSE 3202

CMD [ "npm", "run", "service" ]
