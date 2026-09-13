# Сертификаты Cloudflare

Поддерживаются два способа DNS-01:

1. API Token с правами `Zone:Read` и `DNS:Edit`.
2. Global API Key и email аккаунта.

API Token рекомендуется ограничить нужной зоной. Секрет вводится без echo,
не попадает в аргументы процесса и не записывается в отчёт. Скрипт сначала
ищет существующую пару, затем при необходимости выпускает сертификат зоны и
wildcard:

```text
example.test
*.example.test
```

После выпуска проверяются SAN, срок действия и соответствие ключа. Пути
сертификатов в LucX меняются только после backup и проверки.

## Что означает «автопродление настроено»

Статус считается настроенным только если найдены renewal-конфигурация и
deploy/reload hook действующего ACME-клиента. Сам файл сертификата или флаг в
manifest не являются доказательством.

Проверка Certbot:

```bash
sudo certbot certificates
systemctl is-enabled certbot.timer
systemctl status certbot.timer --no-pager
find /etc/letsencrypt/renewal-hooks/deploy -maxdepth 1 -type f -ls
```

После renewal проверяется сертификат на каждом соответствующем TLS endpoint.
Hook должен возвращать ненулевой код при ошибке пары, конфигурации или службы.

## Смена зоны

При смене зоны проверяются panel, subscription, протокольные endpoint’ы и Naive.
При подтверждённой синхронизации LucX получает только одобренные доменные поля и
пути сертификатов; исходный Naive Caddyfile не редактируется.

Wildcard-заказ имеет вид:

```text
example.test
*.example.test
```

Поддомены первого уровня не добавляются повторно в тот же запрос.
