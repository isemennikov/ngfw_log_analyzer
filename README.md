# NGFW Log Analyzer

Скрипт анализирует логи PT NGFW, экспортированные в формате CSV или JSON, и помогает найти топ-трафик по основным параметрам для написания правил безопасности.


## Возможности
- Автоматическая базовая группировка по полям `srcAddr`, `dstAddr`, `dstPort`, `ipProtocol`, `app`, `securityRuleName`
- Дополнительная сортировка через `--sort-by` для `srcZoneName`, `dstZoneName`, `deviceName`, `contextName`
- Показ топ-N записей через `--top`
- Экспорт результатов в `JSON` и `CSV`
- Поддержка исходных данных как в `CSV`, так и в `JSON`

## Требование
- Экспортируйте логи из СУ PT NGFW в формате CSV.

## Зависимости
- pandas


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
  python3 "ngfw_log_analyzer.py" logs.csv
  ```
- Расширенная сортировка по зонам и девайсу:
  ```bash
  python3 "ngfw_log_analyzer.py" logs.csv --sort-by srcZoneName dstZoneName deviceName
  ```
- Один фильтр
  ```bash
  python3 ngfw_analyzer.py logs.csv --port=443
  ```
- Несколько вместе
  ```bash
  python3 ngfw_analyzer.py logs.csv --srcip=10.0.0.* --port=80,443 --action=allow
  ```
- Wildcard
  ```bash
  python3 ngfw_analyzer.py logs.csv --app=*http* --rule=*deny*
  ```
- Диапазон портов
  ```bash
  python3 ngfw_analyzer.py logs.csv --port=1024-65535 --proto=TCP
  ```

- Комбо с --sort-by
  ```bash
  python3 ngfw_analyzer.py logs.csv --port=4506 --action=allow --sort-by app
  ```

- Топ-30 + экспорт:
  ```bash
  python3 "ngfw_log_analyzer.py" logs.csv --top 30 --export-json out.json --export-csv out.csv
  ```
- Поддерживает и JSON на входе:
  ```bash
  python3 "ngfw_log_analyzer.py" logs.json --sort-by contextName dstZoneName
  ```

## Достпные фильтры 
  | Ключ     | Поле             |
| -------- | ---------------- |
| --srcip  | srcAddr          |
| --dstip  | dstAddr          |
| --port   | dstPort          |
| --proto  | ipProtocol       |
| --app    | app              |
| --rule   | securityRuleName |
| --action | action           |

## Деактивация виртуального окружения
```bash
deactivate
```
