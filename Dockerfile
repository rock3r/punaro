FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/punarod ./cmd/punarod

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/punarod /usr/local/bin/punarod
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/punarod"]
