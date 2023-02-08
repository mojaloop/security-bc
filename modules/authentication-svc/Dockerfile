FROM node:18.13-alpine as builder

# librdkafka build ref from https://gist.github.com/jaihind213/e82d41dc79f52cfa64ca32350bdb27df
ENV LIBRD_VER=2.0.2

# Create app directory
WORKDIR /app

# install main requirements
RUN apk add --no-cache -t build-dependencies bash make wget git gcc g++ python3 libtool libgcc \
	 musl-dev zlib-dev zstd zstd-libs zstd-dev libc-dev autoconf automake openssl pkgconfig

## build and install librdkafka (removing unnecessary libs after)
#RUN apk add --no-cache --virtual .make-deps musl-dev zlib-dev zstd-dev libc-dev \
#    && wget https://github.com/edenhill/librdkafka/archive/v${LIBRD_VER}.tar.gz \
#    && tar -xvf v${LIBRD_VER}.tar.gz && cd librdkafka-${LIBRD_VER} && ./configure --prefix /usr \
#    && make && make install && make clean && rm -rf librdkafka-${LIBRD_VER} && rm -rf v${LIBRD_VER}.tar.gz \
#    && apk del .make-deps

#RUN cd $(npm root -g)/npm \
#    && npm config set unsafe-perm true \
#    && npm install -g node-gyp

RUN npm config set unsafe-perm true && npm install -g node-gyp

# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./
COPY modules/authentication-svc/package*.json ./modules/authentication-svc/
COPY modules/public-types-lib/package*.json ./modules/public-types-lib/

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

COPY --from=builder /app .

# kafka handler, no http server yet
EXPOSE 3201

CMD [ "npm", "run", "start:authentication-svc" ]
