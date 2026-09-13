# ADR-0008: Настройки протоколов изменяемы

**Статус:** принято

LucX вправе нормализовать `settings` и `stream_settings` после обновления.
Integrity защищает структуру inbound, clients identity, listeners и Host metadata,
но не блокирует каждое изменение транспортных параметров.
