# Смена DNS-зоны

В TUI откройте `3. Домены и маршрутизация` и выберите смену DNS-зоны. Введите
старую и новую зоны, например:

```text
example.test -> example.test
```

Будут построены:

```text
panel.example.test -> panel.example.test
sub.example.test -> sub.example.test
```

Сохраняется левая часть имени. Имена вне старой зоны, включая Reality
camouflage SNI, не изменяются. Для обычного TLS SNI из старой зоны обновляется;
Reality `serverNames` сохраняется.

Перед применением создаётся backup. Меняются только публичные URL metadata и
явно подтверждённые transport-поля. Внутренние порты и клиентские данные
сохраняются.
