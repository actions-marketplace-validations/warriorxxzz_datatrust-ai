FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install .
ENTRYPOINT ["datatrust"]


FROM python:3.9
USER nonroot
ENV API_KEY="secret123"
COPY . /app
