# Stage 1: Copy local plugin files instead of cloning from GitHub
FROM alpine:3 AS builder
# Copy the local 'toto' folder (must be in the same directory as Dockerfile)
COPY ./plugins-local /plugins-local

# Stage 2: Build the final Traefik image with the plugin
FROM traefik:v3.3.4
COPY --from=builder /plugins-local /plugins-local