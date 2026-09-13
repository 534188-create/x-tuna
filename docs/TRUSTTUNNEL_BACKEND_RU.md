# TrustTunnel и совместимый backend

## Две разные схемы

LucX TrustTunnel может требовать Client Random prefix. Отдельный совместимый
backend обязан пройти capability probe и реальный protocol-level health-check.
Обычный TCP connect или `--help` бинарного файла недостаточны.

Проверяются:

1. запуск на loopback-порту;
2. TLS 1.3 и ALPN `h2`;
3. HTTP/2 `CONNECT` с корректными данными;
4. отклонение неправильных credentials;
5. обычный браузерный `GET` на сайт-заглушку;
6. внешний маршрут TCP/443;
7. rollback при ошибке.

Исходный LucX inbound, его клиенты, порты и Naive Caddyfile не изменяются.
Публичный маршрут не переключается до успешного CONNECT health-check.

## Диагностика: Настройка → TrustTunnel backend (2 → 6)

Первый пункт подменю читает существующий LucX TrustTunnel: наличие inbound,
его enabled-состояние и соответствие адреса/порта наблюдаемому TCP listener.
IPv6 socket не подтверждает IPv4 listener. Клиенты и credentials не выводятся.
Без аутентифицированного protocol probe статус CONNECT остаётся `not_checked`.

Второй пункт проверяет отдельный optional backend-кандидат. Его отсутствие не
означает, что установленный LucX TrustTunnel не работает. Метаданные бинарника,
готовность свободного staging-порта и результат проверки работающего endpoint
показываются раздельно. Ответ `--help` не считается успешным CONNECT.

Домен optional backend не может перехватить inbound другого протокола.
