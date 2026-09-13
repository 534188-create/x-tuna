# ADR-0002: Неизменяемый Naive Caddyfile

**Статус:** принято

LucX пересоздаёт Naive Caddyfile при reconcile, обновлении, изменении клиента или
сертификата. `x-tuna` контролирует его path, type, owner, mode и hash, но не
патчит и не восстанавливает файл напрямую.
