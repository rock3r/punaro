FROM golang:1.26-alpine@sha256:1a9c10cf505a9e6b1e96ea77ebdbfe79a0f10380181faf88bc3b51d7e4315fae AS build
RUN apk add --no-cache postgresql18-client=18.6-r0
WORKDIR /src
ARG PUNARO_RELEASE
ARG PUNARO_SEQUENCE
ARG PUNARO_CATALOG_SEQUENCE
ARG PUNARO_IMAGE
ARG PUNARO_COMPOSE_SHA256
ARG PUNARO_MIGRATION_SHA256
ARG PUNARO_SKILL_SET_SHA256
ARG PUNARO_PLUGIN_RUNTIME_SHA256
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY plugin.json ./
COPY .codex-plugin/plugin.json ./.codex-plugin/
COPY .claude-plugin/plugin.json ./.claude-plugin/
COPY .mcp.json mcp.json ./
COPY scripts/punaro-plugin-mcp scripts/punaro-plugin-mcp.cmd ./scripts/
COPY skills ./skills
COPY Dockerfile .dockerignore docker-compose.memory-onboarding-e2e.yml ./
COPY scripts/install-client.sh scripts/install-adapter.sh ./scripts/
COPY scripts/verify-deployment-files.sh ./scripts/
COPY deploy/systemd/user/punaro-adapter.service ./deploy/systemd/user/
RUN mkdir -p /home/punaro/tmp \
 && chown 65532:65532 /home/punaro /home/punaro/tmp \
 && chmod 700 /home/punaro /home/punaro/tmp
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.serverBuildRelease=${PUNARO_RELEASE} -X main.serverBuildSequence=${PUNARO_SEQUENCE} -X main.serverBuildCatalogSequence=${PUNARO_CATALOG_SEQUENCE} -X main.serverBuildImage=${PUNARO_IMAGE} -X main.serverBuildComposeSHA256=${PUNARO_COMPOSE_SHA256} -X main.serverBuildMigrationSHA256=${PUNARO_MIGRATION_SHA256}" -o /out/punaro ./cmd/punaro \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punarod ./cmd/punarod \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-migrate ./cmd/punaro-migrate \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-admin ./cmd/punaro-admin \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.adapterBuildRelease=${PUNARO_RELEASE} -X main.adapterExpectedSkillSetDigest=${PUNARO_SKILL_SET_SHA256} -X main.adapterExpectedPluginRuntimeDigest=${PUNARO_PLUGIN_RUNTIME_SHA256}" -o /out/punaro-adapter ./cmd/punaro-adapter \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.telegramBuildRelease=${PUNARO_RELEASE} -X main.telegramBuildSequence=${PUNARO_SEQUENCE} -X main.telegramBuildCatalogSequence=${PUNARO_CATALOG_SEQUENCE}" -o /out/punaro-telegram ./cmd/punaro-telegram \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-trusted-attachment ./cmd/punaro-trusted-attachment \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-relay-adopt-prepare ./cmd/punaro-relay-adopt-prepare

FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
ARG PUNARO_RELEASE
LABEL org.opencontainers.image.version="${PUNARO_RELEASE}"
COPY --from=build /out/punaro /usr/local/bin/punaro
COPY --from=build /out/punarod /usr/local/bin/punarod
COPY --from=build /out/punaro-migrate /usr/local/bin/punaro-migrate
COPY --from=build /out/punaro-admin /usr/local/bin/punaro-admin
COPY --from=build /out/punaro-adapter /usr/local/bin/punaro-adapter
COPY --from=build /out/punaro-telegram /usr/local/bin/punaro-telegram
COPY --from=build /out/punaro-trusted-attachment /usr/local/bin/punaro-trusted-attachment
COPY --from=build /out/punaro-relay-adopt-prepare /usr/local/bin/punaro-relay-adopt-prepare
USER nonroot:nonroot
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/punarod"]
