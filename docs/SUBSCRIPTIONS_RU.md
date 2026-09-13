# Подписки и совместимость клиентов

## Поток запроса

```text
клиент → публичный clean URL → HAProxy/sidecar → LucX subscription service
```

Внутренний порт LucX не должен попадать в ссылку клиента, если публикация
настроена через внешний TCP/443. Sidecar работает только на loopback и не
должен быть доступен напрямую из интернета.

## Правила преобразования

- `qwdtt://` и `wdtt://` не передаются в клиентские подписки;
- TrustTunnel публикуется только как TCP/HTTPS (`h2`), QUIC/HTTP3 исключается;
- наличие `congestion_control` в TrustTunnel URI запрещает выдачу независимо
  от значения: в Throne 1.2.4 этот ключ включает QUIC; регистр повторных ключей
  и percent encoding не должны скрывать опасные параметры;
- Throne получает преобразованный AWG `wg://` с сырыми `/`, `+`, `=`;
- Mieru `traffic-pattern` для Throne декодируется до исходного Base64;
- простой VMess gRPC/TLS/h2 из известной формы LucX v2 JSON преобразуется для
  Throne в URI с `serviceName`, сохраняя UUID, endpoint, SNI, шифр и имя;
- AnyTLS получает public Host domain/port вместо внутреннего listener port;
- NekoBox, Clash и Mihomo сохраняют поддерживаемый LucX-формат;
- имя подключения, fragment и credentials не переименовываются;
- ошибка преобразования возвращает оригинальный ответ LucX.

## Проверка

Нельзя проверять только HTTP-код. Нужно отдельно проверить статус, формат,
число ожидаемых протоколов, порт AnyTLS, отсутствие qWDTT/QUIC и корректность
AWG/Mieru. Полный набор проверок находится в `tests/test_sidecar.py`.

## Публичные пути

Операторская ссылка должна использовать внешний clean URL без внутреннего порта:

```text
https://sub.example.test/sub/<subscription-id>
https://sub.example.test/clash/<subscription-id>
https://sub.example.test/json/<subscription-id>
https://sub.example.test/awg/<subscription-id>?format=conf
```

`<subscription-id>` является placeholder и не записывается в документацию,
отчёты или команды в настоящем виде.

## Матрица клиентов

| Клиент | Ожидаемый результат |
|---|---|
| Throne | AWG `wg://` и исправленный Mieru Base64 |
| NekoBox | поддерживаемый LucX AWG/TrustTunnel формат |
| Clash/Mihomo | валидный YAML без qWDTT |
| другой клиент | исходный формат или безопасный fail-open |

User-Agent может выбирать формат подписки, но не является основанием для firewall
или сетевой маршрутизации. Sidecar слушает только loopback, проверяет Host и
разрешённые пути, не печатает тело подписки и открывает SQLite только read-only.

Для выбранного клиента Throne 1.2.4 дополнительно проверены исходники точного
тега. Его URI importer отправляет VMess/Trojan XHTTP в ядро без такого транспорта;
VMess gRPC в v2rayN JSON теряет service name, хотя URI-форма его поддерживает.
Sidecar преобразует только распознанную простую форму LucX в такой URI:
`grpc`, `type=none`, TLS/h2, пустые authority/host и дополнительные TLS-параметры.
MultiMode, неизвестные поля, сложный TLS и повреждённые формы остаются исходными;
это не подтверждает их совместимость. Другие User-Agent это преобразование
не получают. Общий выбор формата по слову Throne сохранён, но исследован именно
код версии 1.2.4; импорт и соединение release asset ещё требуют проверки.

Официальный `Throne-1.2.4-windows64.zip` проверен по опубликованному GitHub
SHA-256 `89d32f3a557849641b466d3c2f0ac69dfc02ec8309a129289290e8fcca4b7b32`.
В архиве присутствует libcronet.dll, а buildinfo ThroneCore содержит
`with_naive_outbound`. Зафиксированы также replacements модулей: встроенный
Xray использует fork Throne с commit `735fffaa66af`. Проверка состава архива
не подтверждает импорт URI или соединение; программа ещё не запускалась.
Источник: [официальный релиз Throne 1.2.4](https://github.com/throneproj/Throne/releases/tag/1.2.4).
Legacy Windows build не включает Naive. TT importer не читает `client_random_prefix`,
поэтому маршрут, требующий этот префикс, нельзя объявлять совместимым без другого
проверенного backend-контракта. Испытания Xray не заменяют приёмку самого клиента.
Основание: [код Throne 1.2.4](https://github.com/throneproj/Throne/tree/33777e27b77cb62ef8c98a47d8ea4601de0c1983)
и закреплённые в нём версии ядер; запуск release asset ещё требуется.

## Негативные проверки

Обязательны тесты пустого ответа, повреждённого Base64/TLV, неизвестного клиента,
невалидного пути, слишком большого payload и недоступного upstream. Ошибка одной
строки не должна ломать выдачу всей подписки.
