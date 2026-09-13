# Инструменты разработчика

Каталог содержит вспомогательные программы для сборки, статической проверки и
разрешённых интеграционных тестов. Инструменты с `live_` и `external_` в имени
могут обращаться к серверу и не запускаются автоматически в локальном suite.

## Основные инструменты

- `build_installer.py` — собирает автономный shell-файл;
- `compare_lucx_database_snapshots.py` — сравнивает только безопасные метаданные;
- `live_subscription_acceptance.py` — проверяет форматы подписок без вывода URI;
- `live_external_trusttunnel_probe.py` — проверяет внешний TrustTunnel;
- `trusttunnel_staging_probe.py` — проверяет staged backend;
- `external_sni_probe.py` — проверяет SNI-маршруты.

Перед запуском любого live-инструмента требуется отдельное разрешение и
проверка адреса назначения. Production secrets не передаются через argv.

`live_external_trusttunnel_probe.py` требует явные аргументы `HOST PORT SNI` и
не содержит адресов рабочих серверов по умолчанию.
