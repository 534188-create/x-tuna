# ADR-0003: Detached update-worker

**Статус:** принято

Официальный updater может остановить `x-ui` и вызвать reboot. Обновление и
post-update repair выполняются в отдельном systemd template unit, а TUI только
создаёт задание и показывает состояние.
