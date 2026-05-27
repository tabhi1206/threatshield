### Build stage
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY src ./src
COPY public ./public
COPY vite.config.* ./
RUN npm ci
RUN npm run build

### Production stage
FROM nginx:1.25-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
