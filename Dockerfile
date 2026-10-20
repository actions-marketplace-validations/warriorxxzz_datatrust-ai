FROM python:3.10-slim AS builder
WORKDIR /app
COPY . .
RUN pip install --user .

FROM python:3.10-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
RUN useradd -m nonroot && chown -R nonroot:nonroot /app
USER nonroot
ENTRYPOINT ["datatrust"]
