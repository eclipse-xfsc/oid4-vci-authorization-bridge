FROM golang as build

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /preauthbridge

FROM alpine as runner

WORKDIR /app

COPY --from=build /preauthbridge /preauthbridge

CMD ["/preauthbridge"]