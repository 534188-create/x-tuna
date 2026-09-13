from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def make_target(root: Path) -> Path:
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8")
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/ssh/sshd_config").write_text("Port 49283\n# Port 22\n", encoding="utf-8")
    db = root / "etc/x-ui/x-ui.db"
    db.parent.mkdir(parents=True)
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
    connection.execute(
        "CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, remark TEXT, enable INTEGER, listen TEXT, port INTEGER, settings TEXT, stream_settings TEXT, share_addr TEXT, share_addr_strategy TEXT)"
    )
    settings = {
        "webDomain": "panel.example.com",
        "webPort": "2083",
        "webBasePath": "/secret/",
        "webListen": "",
        "webCertFile": "/cert/fullchain.pem",
        "webKeyFile": "/cert/privkey.pem",
        "subDomain": "sub.example.com",
        "subPort": "2096",
        "subListen": "",
        "subPath": "/sub/",
        "subCertFile": "/cert/fullchain.pem",
        "subKeyFile": "/cert/privkey.pem",
    }
    connection.executemany("INSERT INTO settings(key,value) VALUES (?,?)", settings.items())
    rows = [
        (
            1,
            "vless",
            "Reality",
            1,
            "127.0.0.1",
            54703,
            json.dumps({"clients": [{"id": "must-not-leak"}], "domain": "api.example.com", "sharePort": 443}),
            json.dumps({"network": "tcp", "security": "reality", "realitySettings": {"privateKey": "must-not-leak"}}),
            "api.example.com",
            "custom",
        ),
        (
            2,
            "hysteria",
            "HY2",
            1,
            "",
            443,
            json.dumps({"domain": "cloud.example.com"}),
            json.dumps({"network": "udp", "version": 2}),
            "cloud.example.com",
            "custom",
        ),
        (
            3,
            "mieru",
            "SITE mieru",
            1,
            "",
            27015,
            json.dumps({"domain": "game.example.com", "portBindings": [{"portRange": "27015-27035", "protocol": "TCP"}], "clients": [{"password": "must-not-leak"}]}),
            "{}",
            "game.example.com",
            "custom",
        ),
        (
            4,
            "qwdtt",
            "qWDTT",
            1,
            "",
            56000,
            json.dumps({"domain": "media.example.com", "listenAddr": "0.0.0.0:56000", "wgPort": 56001, "listenRaw": "0.0.0.0:56003", "password": "must-not-leak"}),
            "{}",
            "media.example.com",
            "custom",
        ),
        (
            5,
            "awg",
            "SITE awg",
            1,
            "",
            56712,
            json.dumps({"domain": "userapi.example.com", "privateKey": "must-not-leak"}),
            "{}",
            "userapi.example.com",
            "custom",
        ),
    ]
    connection.executemany(
        "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    connection.commit()
    connection.close()
    return db
