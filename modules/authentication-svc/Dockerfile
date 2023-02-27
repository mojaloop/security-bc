FROM node:18.13.0-alpine AS builder

# Create the project directory inside the container.
WORKDIR /app

RUN apk add --no-cache -t build-dependencies git make gcc g++ python3 \
    libtool autoconf pkgconfig automake librdkafka-dev bash # wget tar xz

RUN cd $(npm root -g)/npm
RUN npm config set unsafe-perm true
RUN npm install -g node-gyp

# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./
COPY modules/public-types-lib/package*.json ./modules/public-types-lib/
COPY modules/authentication-svc/package*.json ./modules/authentication-svc/

# If you are building your code for production
#RUN npm ci --only=production
RUN npm install

########################################
# Copy code and build

# root tsconfig.json
COPY tsconfig.json ./

# copy required supporting modules/packages (especially private ones not published to npm)
COPY modules/public-types-lib ./modules/public-types-lib

# copy service code
COPY modules/authentication-svc ./modules/authentication-svc

# build
RUN npm run build

RUN ls -la ./modules/authentication-svc/dist


FROM node:18.13-alpine
WORKDIR /app

RUN apk add librdkafka

COPY --from=builder /app .

# kafka handler, no http server yet
EXPOSE 3201

CMD [ "npm", "run", "start:authentication-svc" ]
