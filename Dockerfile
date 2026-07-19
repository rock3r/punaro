FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
RUN apk add --no-cache postgresql18-client
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro ./cmd/punaro \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punarod ./cmd/punarod \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-migrate ./cmd/punaro-migrate \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-admin ./cmd/punaro-admin \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-adapter ./cmd/punaro-adapter \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-directory ./cmd/punaro-directory \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-telegram ./cmd/punaro-telegram \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punaro-attachment ./cmd/punaro-attachment

FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
COPY --from=build /out/punaro /usr/local/bin/punaro
COPY --from=build /out/punarod /usr/local/bin/punarod
COPY --from=build /out/punaro-migrate /usr/local/bin/punaro-migrate
COPY --from=build /out/punaro-admin /usr/local/bin/punaro-admin
COPY --from=build /out/punaro-adapter /usr/local/bin/punaro-adapter
COPY --from=build /out/punaro-directory /usr/local/bin/punaro-directory
COPY --from=build /out/punaro-telegram /usr/local/bin/punaro-telegram
COPY --from=build /out/punaro-attachment /usr/local/bin/punaro-attachment
USER nonroot:nonroot
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/punarod"]
