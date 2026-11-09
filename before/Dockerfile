# VULN 8: single stage, full toolchain in the image, mutable tag, runs as root.
FROM golang:latest
WORKDIR /app
COPY . .
RUN go build -o server .
EXPOSE 8080
CMD ["./server"]
