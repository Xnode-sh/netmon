# netmon

Windows LAN monitor — инвентаризация устройств, DNS-лог, захват трафика, роутер-сёрф.

Требует прав **администратора**. Работает только на Windows (PktMon, ETW).

## Установка

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## Использование

```bash
# инвентаризация устройств в сети
python netmon.py discover

# DNS-лог в реальном времени (через ETW)
python netmon.py dns

# захват трафика
python netmon.py traffic

# pcap для Wireshark
python netmon.py pcap

# роутер: telnet + базовая инфа
python netmon.py router

# фоновый мониторинг
python netmon.py watch

# отчёт по собранным данным
python netmon.py report
```

## Структура

```
netmon.py       главный скрипт (subcommands: env/discover/dns/traffic/pcap/router/watch/report)
oui.py          база MAC → производитель (OUI)
dns_tail.ps1    PowerShell-хвост DNS-событий из ETW
data/           SQLite БД (в .gitignore)
logs/           логи (в .gitignore)
captures/       pcap-файлы (в .gitignore)
```

## Зависимости

- Python 3.10+
- Windows: `PktMon.exe` (встроен с Win10 1809+)
- ETW-канал: `Microsoft-Windows-DNS-Client/Operational`
- SQLite (встроен в stdlib)

## Правовое

Только мониторинг своей сети. Не используй для перехвата чужого трафика.
