# Обновление LucX

## Назначение

Автоматическое обновление через `x-tuna` сейчас недоступно: официальный updater
может перезагрузить сервер, а проверенного адаптера без reboot ещё нет.
Меню и `--update-lucx` показывают причину до выбора источника и подтверждения.
`--yes` и поля задания не обходят запрет. Сервер при этом не изменяется.

Защита повторяется в worker: старое задание тоже не запускается. Его descriptor,
payload, marker и status сохраняются; `queued` в старом JSON не означает выполнение.
`update_source_status` возвращает `automatic_update_available=false` и причину.

## Схема

```text
x-tuna -> проверка доступности безопасного адаптера -> отказ до изменений
старое worker-задание -> повторная проверка -> отказ до запуска updater
```

## Источники

Механика SourceCraft, GitHub, HTTPS proxy и собственного HTTPS tar-архива
сохранена, но штатный автоматический путь до неё не доходит.
Каждый архив проверяется по размеру, типу элементов, shebang, наличию `update.sh`
и безопасным путям. Symlink, hardlink, абсолютные пути и path traversal запрещены.

## Состояния worker

| Состояние | Значение |
|---|---|
| `queued` | задание записано, updater ещё не запущен |
| `running_updater` | работает официальный updater |
| `running_repair` | восстанавливается внешняя обвязка |
| `complete` | updater и repair прошли health-check |
| `failed` | операция остановлена, marker и диагностика сохранены |

Состояние хранится в `/var/lib/lucx-post-configurator/update-status.json`.

## Отказоустойчивость

`lucx-post-update@.service` и состояния очереди сохранены для будущего безопасного
адаптера; полный detached lifecycle пока не подтверждён. Repair после отдельно
разрешённого обновления остаётся самостоятельной операцией. Автоматическая
перезагрузка не является частью допустимого сценария x-tuna.

Marker удаляется только после проверки LucX, ingress, listeners, сертификатов,
firewall, подписок и заглушек. При ошибке updater repair не имитирует успех.

## Проверка результата

```bash
sudo lucx-sub-repair --check
sudo x-tuna --validate
cat /var/lib/lucx-post-configurator/update-status.json
journalctl -u lucx-post-update-repair.service --no-pager -n 100
```

Не запускайте новый updater поверх задания в состоянии `failed` и не удаляйте
pending marker вручную.
