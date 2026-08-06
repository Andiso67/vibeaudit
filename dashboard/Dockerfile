# Dashboard de VibeAudit (Next.js) — imagen de producción multi-stage.
# En desarrollo se usa docker-compose.dev.yml con npm run dev y volúmenes.
#
# NEXT_PUBLIC_API_URL se embebe en el bundle en build time: hay que pasarla
# como build arg (lo hace docker-compose.prod.yml desde el .env).

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS build
WORKDIR /app
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json /app/next.config.mjs ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["npm", "start"]
