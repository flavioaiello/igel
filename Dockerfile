FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
RUN cargo build --release && strip target/release/igel

FROM alpine:3.21
RUN addgroup -S igel && adduser -S igel -G igel
COPY --from=build /src/target/release/igel /usr/local/bin/igel
USER igel
ENTRYPOINT ["igel"]
CMD ["/etc/igel/igel.toml"]
