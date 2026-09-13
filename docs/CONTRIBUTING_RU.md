# Участие в разработке

## Перед изменением

- прочитайте `ARCHITECTURE.md`, `CONFIGURATION_RU.md` и `SECURITY_MODEL_RU.md`;
- найдите связанный тест и добавьте регрессию до изменения кода;
- определите write-set, backup и rollback;
- не используйте реальные серверные данные в fixtures.

## Требования к изменению

- объяснительный текст пишется на русском;
- имена кода, flags, paths и protocol identifiers не переводятся;
- неизвестная схема блокируется, а не угадывается;
- каждое изменение интеграции имеет тест на ошибку и rollback;
- документация, acceptance и TUI обновляются вместе с поведением.

## Проверка перед commit

```bash
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
python3 tools/build_installer.py
```

Перед commit просмотрите `git diff --check`, список файлов и secret scan.
