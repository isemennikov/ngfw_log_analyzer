# NGFW Log Analyzer

Скрипт анализирует логи PT NGFW, экспортированные в формате CSV или JSON, и помогает быстро найти топ-трафик по основным параметрам для написания правил безопасности.

## Требование
- Экспортируйте логи из СУ PT NGFW в формате CSV.

## Установка
1. Создайте и активируйте виртуальное окружение:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Установите зависимость:
   ```bash
   pip install pandas
   ```

## Запуск
- Базовый запуск (группировка по srcAddr, dstAddr, dstPort, ipProtocol, app, securityRuleName):
  ```bash
  python3 "ngfw_log analyzer.py" logs.csv
  ```
- Расширенная сортировка по зонам и девайсу:
  ```bash
  python3 "ngfw_log analyzer.py" logs.csv --sort-by srcZoneName dstZoneName deviceName
  ```
- Топ-30 + экспорт:
  ```bash
  python3 "ngfw_log analyzer.py" logs.csv --top 30 --export-json out.json --export-csv out.csv
  ```
- Поддерживает и JSON на входе:
  ```bash
  python3 "ngfw_log analyzer.py" logs.json --sort-by contextName dstZoneName
  ```

> Если скрипт переименован в `ngfw_analyzer.py`, замените имя файла в командах на `ngfw_analyzer.py`.

## Возможности
- Автоматическая базовая группировка по полям `srcAddr`, `dstAddr`, `dstPort`, `ipProtocol`, `app`, `securityRuleName`
- Дополнительная сортировка через `--sort-by` для `srcZoneName`, `dstZoneName`, `deviceName`, `contextName`
- Показ топ-N записей через `--top`
- Экспорт результатов в `JSON` и `CSV`
- Поддержка исходных данных как в `CSV`, так и в `JSON`

## Деактивация виртуального окружения
```bash
deactivate
```

## Зависимости
- pandas
