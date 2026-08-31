FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o atp-server ./cmd

EXPOSE 8080

CMD ["/app/atp-server", "--port=8080"]