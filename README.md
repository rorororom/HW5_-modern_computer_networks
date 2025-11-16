# HW5 – TLS поверх TCP + NSS Key Log

## Смысл
![PIUPUP](PNG/i.webp)


Мини-приложение на Python: echo-сервер и клиент с поддержкой TLS и логированием сессионных ключей (NSS Key Log).

### 1) Самоподписанный сертификат 
```
    openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout server.key -out server.crt -days 7 \
    -subj "/CN=localhost"
```

### 2) Включить логирование ключей 
```
    export SSLKEYLOGFILE="$(pwd)/sslkeys.log"
```

### 3) Сервер 
```
    python -m network_app.server --host 127.0.0.1 --port 8888 \
    --tls --cert server.crt --key server.key
```

### 4) Клиент 
```
    python -m network_app.client --host 127.0.0.1 --port 8888 --tls --insecure
```


