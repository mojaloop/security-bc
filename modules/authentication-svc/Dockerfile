FROM node:16.13 as builder

# Create app directory
WORKDIR /app

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


FROM node:16.13
WORKDIR /app

COPY --from=builder /app .

# kafka handler, no http server yet
# EXPOSE 8080

CMD [ "node", "dist/application/index.js" ]
