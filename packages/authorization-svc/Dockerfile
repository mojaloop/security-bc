FROM node:20.10.0-alpine3.18 AS builder

# Create the project directory inside the container.
WORKDIR /app

RUN apk add --no-cache -t build-dependencies git make gcc g++ python3 \
    libtool autoconf pkgconfig automake librdkafka-dev bash # wget tar xz

RUN cd $(npm root -g)/npm
#RUN npm config set unsafe-perm true
RUN npm install -g node-gyp

# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./
COPY packages/public-types-lib/package*.json ./packages/public-types-lib/
COPY packages/client-lib/package*.json ./packages/client-lib/
COPY packages/authorization-svc/package*.json ./packages/authorization-svc/

# If you are building your code for production
#RUN npm ci --only=production
RUN BUILD_LIBRDKAFKA=0 npm install

# Note on BUILD_LIBRDKAFKA:
#   Use BUILD_LIBRDKAFKA=0 only if we have installed librdkafka-dev in
#   the builder image and librdkafka in the final image

########################################
# Copy code and build

# root tsconfig.json
COPY tsconfig.json ./

# copy required supporting packages/packages (especially private ones not published to npm)
COPY packages/public-types-lib ./packages/public-types-lib
COPY packages/client-lib ./packages/client-lib

# copy service code
COPY packages/authorization-svc ./packages/authorization-svc

# build
RUN npm run build

RUN ls -la ./packages/authorization-svc/dist


FROM node:20.10.0-alpine3.18
WORKDIR /app
RUN mkdir /app/data

RUN apk add librdkafka

COPY --from=builder /app .

# kafka handler, no http server yet
EXPOSE 3202

CMD [ "npm", "run", "start:authorization-svc" ]
