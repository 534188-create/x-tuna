# Словарь терминов

| Термин | Значение |
|---|---|
| inbound | входящее подключение LucX |
| outbound | исходящий маршрут LucX/Xray |
| listener | локальный TCP/UDP socket процесса |
| endpoint | публичный адрес и порт для клиента |
| SNI | имя TLS-сервера в ClientHello |
| SNI collision | совпадение SNI браузера и VPN |
| transport | транспорт протокола: WS, gRPC, XHTTP, TCP и другие |
| passthrough | передача TLS без завершения на frontend |
| termination | завершение TLS на frontend |
| re-encryption | новое TLS-соединение frontend к backend |
| fallback | запасной обработчик обычного HTTP или неподходящего трафика |
| decoy | сайт-заглушка |
| sidecar | вспомогательный сервис рядом с LucX |
| write-set | точный набор объектов, разрешённых к изменению |
| immutable-set | объекты, изменение которых запрещено |
| drift | отличие текущего состояния от baseline |
| rebaseline | запись нового проверенного baseline |
| staging | временная область до commit |
| health-check | проверка живой службы и маршрута |
| fail-open | возврат исходного рабочего содержимого при ошибке |
| fail-closed | запрет маршрута при неопределённости |
| deploy hook | команда после выдачи сертификата |
| renewal hook | применение обновлённого сертификата |
| worker | независимый systemd-процесс долгой операции |
| marker | файл незавершённой обязательной фазы |
