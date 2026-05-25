#!/usr/bin/env python3
"""
NGFW Log Analyzer
=================
Анализирует логи NGFW в форматах CSV или JSON.
Показывает топ-трафик по ключевым полям для написания правил безопасности.

Использование:
  python3 ngfw_analyzer.py <файл.csv или файл.json> [опции]

Опции:
  --sort-by FIELD [FIELD ...]   Поля группировки (помимо базовых)
  --top N                       Показать топ N записей (по умолчанию: 20)
  --export-json FILE            Экспорт результатов в JSON
  --export-csv FILE             Экспорт результатов в CSV
  --min-rows N                  Минимум строк для анализа (по умолчанию: 30)
  --no-color                    Отключить цветной вывод

Поля для --sort-by:
  Базовые (всегда включены):
    srcAddr, dstAddr, dstPort, ipProtocol, app, securityRuleName

  Дополнительные (через --sort-by):
    deviceName, contextName, srcZoneName, dstZoneName
    srcAddr, dstAddr, dstPort, ipProtocol, app, securityRuleName

Примеры:
  python3 ngfw_analyzer.py logs.csv
  python3 ngfw_analyzer.py logs.csv --sort-by srcZoneName dstZoneName
  python3 ngfw_analyzer.py logs.csv --sort-by deviceName srcAddr dstPort --top 30
  python3 ngfw_analyzer.py logs.json --export-json result.json --export-csv result.csv
"""

import argparse
import json
import sys
import os
from collections import Counter
from datetime import datetime, timezone

try:
    import pandas as pd
except ImportError:
    print("Ошибка: установите pandas -> pip install pandas")
    sys.exit(1)

# ─── Цвета ────────────────────────────────────────────────────────────────────

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    BG_DARK = "\033[40m"

USE_COLOR = True

def c(color: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{Colors.RESET}"

# ─── Константы ────────────────────────────────────────────────────────────────

BASE_FIELDS = ["srcAddr", "dstAddr", "dstPort", "ipProtocol", "app", "securityRuleName"]

EXTRA_FIELDS_ALLOWED = [
    "deviceName", "contextName", "srcZoneName", "dstZoneName",
    "srcAddr", "dstAddr", "dstPort", "ipProtocol", "app", "securityRuleName"
]

PROTO_MAP = {
    "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE",
    "50": "ESP", "51": "AH", "58": "ICMPv6", "89": "OSPF", "132": "SCTP"
}

FIELD_LABELS = {
    "srcAddr":          "Src IP",
    "dstAddr":          "Dst IP",
    "dstPort":          "Dst Port",
    "ipProtocol":       "Protocol",
    "app":              "Application",
    "securityRuleName": "Security Rule",
    "deviceName":       "Device",
    "contextName":      "Context",
    "srcZoneName":      "Src Zone",
    "dstZoneName":      "Dst Zone",
}

# ─── Загрузка данных ──────────────────────────────────────────────────────────

def detect_csv_separator(path: str) -> str:
    """Определяет разделитель CSV-файла."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
    for sep in [";", ",", "\t", "|"]:
        if sep in first_line:
            return sep
    return ","

def load_file(path: str) -> pd.DataFrame:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, list):
            df = pd.DataFrame(raw)
        elif isinstance(raw, dict):
            # попробуем найти список внутри
            for v in raw.values():
                if isinstance(v, list):
                    df = pd.DataFrame(v)
                    break
            else:
                df = pd.DataFrame([raw])
        else:
            raise ValueError("Неподдерживаемый формат JSON")
    elif ext in (".csv", ".tsv", ".log", ""):
        sep = detect_csv_separator(path)
        df = pd.read_csv(path, sep=sep, dtype=str, low_memory=False)
    else:
        raise ValueError(f"Неизвестный формат файла: {ext}")
    return df

# ─── Нормализация ─────────────────────────────────────────────────────────────

def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    """Приводит значения к читаемому виду."""
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    # Нормализуем протокол
    if "ipProtocol" in df.columns:
        df["ipProtocol"] = df["ipProtocol"].astype(str).apply(
            lambda x: PROTO_MAP.get(x.strip(), x.strip())
        )
    # Пустые значения
    df = df.fillna("—")
    df = df.replace(r"^\s*$", "—", regex=True)
    return df

# ─── Анализ ───────────────────────────────────────────────────────────────────

def analyze(df: pd.DataFrame, group_fields: list[str], top_n: int) -> pd.DataFrame:
    """Группирует и считает события по заданным полям."""
    existing = [f for f in group_fields if f in df.columns]
    missing  = [f for f in group_fields if f not in df.columns]
    if missing:
        print(c(Colors.YELLOW, f"  ⚠  Поля не найдены в файле и будут пропущены: {', '.join(missing)}"))
    if not existing:
        raise ValueError("Ни одно из запрошенных полей не найдено в данных")

    grouped = (
        df.groupby(existing, dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .head(top_n)
        .reset_index(drop=True)
    )
    grouped.index = grouped.index + 1  # нумерация с 1
    return grouped, existing

# ─── Отображение ──────────────────────────────────────────────────────────────

def bar(count: int, max_count: int, width: int = 30) -> str:
    if max_count == 0:
        return ""
    filled = int(round(count / max_count * width))
    bar_str = "█" * filled + "░" * (width - filled)
    return bar_str

def col_width(series: pd.Series, header: str, max_w: int = 40) -> int:
    max_val = series.astype(str).str.len().max()
    return min(max(max_val, len(header)) + 2, max_w)

def print_table(result: pd.DataFrame, fields: list[str], top_n: int, total_rows: int):
    if result.empty:
        print(c(Colors.YELLOW, "  Нет данных для отображения."))
        return

    max_count = result["count"].max()
    headers   = ["#"] + [FIELD_LABELS.get(f, f) for f in fields] + ["Count", "Bar (relative)"]

    # Ширины колонок
    widths = [4]
    for f in fields:
        widths.append(col_width(result[f], FIELD_LABELS.get(f, f)))
    widths += [12, 34]

    def row_str(cells, color=None):
        parts = []
        for cell, w in zip(cells, widths):
            s = str(cell)
            if len(s) > w - 1:
                s = s[:w - 4] + "..."
            parts.append(s.ljust(w))
        line = "│ " + " │ ".join(parts) + " │"
        return c(color, line) if color else line

    sep_line = "├─" + "─┼─".join("─" * w for w in widths) + "─┤"
    top_line = "┌─" + "─┬─".join("─" * w for w in widths) + "─┐"
    bot_line = "└─" + "─┴─".join("─" * w for w in widths) + "─┘"

    print(c(Colors.CYAN, top_line))
    print(row_str(headers, Colors.BOLD + Colors.CYAN if USE_COLOR else None))
    print(c(Colors.CYAN, sep_line))

    for i, row in result.iterrows():
        cnt   = int(row["count"])
        pct   = cnt / total_rows * 100
        b     = bar(cnt, max_count)
        # show full integer count (no K/M/B shortening)
        cells = [str(i)] + [str(row[f]) for f in fields] + [f"{cnt:,} ({pct:.1f}%)", b]

        if i == 1:
            color = Colors.YELLOW
        elif i <= 3:
            color = Colors.GREEN
        else:
            color = None
        print(row_str(cells, color))

    print(c(Colors.CYAN, bot_line))

# ─── Экспорт ──────────────────────────────────────────────────────────────────

def export_results(result: pd.DataFrame, fields: list[str],
                   json_path: str | None, csv_path: str | None,
                   total_rows: int):
    export_df = result.copy()
    export_df.insert(0, "rank", range(1, len(result) + 1))
    export_df["percent"] = (export_df["count"] / total_rows * 100).round(2)

    if json_path:
        records = export_df.to_dict(orient="records")
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "total_log_rows": total_rows,
            "group_fields": fields,
            "results": records
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        print(c(Colors.GREEN, f"  ✓  JSON экспорт: {json_path}"))

    if csv_path:
        export_df.to_csv(csv_path, index=False, encoding="utf-8-sig")
        print(c(Colors.GREEN, f"  ✓  CSV  экспорт: {csv_path}"))

# ─── Шапка / Статистика ───────────────────────────────────────────────────────

def print_header(path: str, total: int, fields: list[str], top_n: int):
    width = 80
    print()
    print(c(Colors.BOLD + Colors.BLUE, "=" * width))
    print(c(Colors.BOLD + Colors.BLUE, "  NGFW LOG ANALYZER — Анализ трафика для выработки правил безопасности"))
    print(c(Colors.BOLD + Colors.BLUE, "=" * width))
    print(c(Colors.GREY, f"  Файл      : {path}"))
    print(c(Colors.GREY, f"  Строк     : {total}"))
    print(c(Colors.GREY, f"  Группировка: {', '.join(fields)}"))
    print(c(Colors.GREY, f"  Топ       : {top_n}"))
    print(c(Colors.GREY, f"  Время     : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"))
    print(c(Colors.BOLD + Colors.BLUE, "=" * width))
    print()

def print_summary(df: pd.DataFrame):
    """Краткая сводка по данным."""
    print(c(Colors.BOLD, "\n📊  ОБЩАЯ СТАТИСТИКА"))
    print(c(Colors.GREY, "─" * 50))

    if "action" in df.columns:
        actions = df["action"].value_counts()
        for act, cnt in actions.items():
            icon = "✅" if str(act).lower() == "allow" else "🚫"
            print(f"  {icon} {str(act).upper():10s}: {cnt:>6} событий")

    if "ipProtocol" in df.columns:
        protos = df["ipProtocol"].value_counts().head(5)
        print(c(Colors.GREY, "\n  Протоколы (топ-5):"))
        for p, cnt in protos.items():
            print(f"    {str(p):10s}: {cnt}")

    if "app" in df.columns:
        apps = df["app"].value_counts().head(5)
        print(c(Colors.GREY, "\n  Приложения (топ-5):"))
        for a, cnt in apps.items():
            print(f"    {str(a):20s}: {cnt}")
    print()

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Анализатор логов NGFW (CSV/JSON) для выработки правил безопасности",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("file", help="Путь к файлу лога (.csv или .json)")
    parser.add_argument(
        "--sort-by", nargs="+", metavar="FIELD",
        help=(
            "Дополнительные поля группировки. "
            f"Доступные: {', '.join(EXTRA_FIELDS_ALLOWED)}"
        )
    )
    parser.add_argument("--top", type=int, default=20, metavar="N",
                        help="Показать топ N записей (по умолчанию: 20)")
    parser.add_argument("--export-json", metavar="FILE",
                        help="Экспортировать результаты в JSON-файл")
    parser.add_argument("--export-csv", metavar="FILE",
                        help="Экспортировать результаты в CSV-файл")
    parser.add_argument("--min-rows", type=int, default=30, metavar="N",
                        help="Минимальное количество строк для анализа (по умолчанию: 30)")
    parser.add_argument("--no-color", action="store_true",
                        help="Отключить цветной вывод")

    args = parser.parse_args()

    global USE_COLOR
    if args.no_color or not sys.stdout.isatty():
        USE_COLOR = False

    # ── Загрузка ──────────────────────────────────────────────────────────────
    print(c(Colors.CYAN, f"\n  Загрузка: {args.file} ..."))
    try:
        df = load_file(args.file)
    except FileNotFoundError:
        print(c(Colors.RED, f"  ❌ Файл не найден: {args.file}"))
        sys.exit(1)
    except Exception as e:
        print(c(Colors.RED, f"  ❌ Ошибка загрузки: {e}"))
        sys.exit(1)

    total_rows = len(df)

    # ── Проверка минимального количества строк ────────────────────────────────
    if total_rows <= args.min_rows:
        print(c(Colors.YELLOW,
            f"  ⚠  Файл содержит {total_rows} строк(и), что не превышает "
            f"минимально допустимый порог {args.min_rows}.\n"
            f"     Анализ может быть ненадёжным. Используйте --min-rows N чтобы изменить порог."
        ))
        if total_rows == 0:
            print(c(Colors.RED, "  ❌ Файл пуст. Завершение."))
            sys.exit(1)
    else:
        print(c(Colors.GREEN, f"  ✓  Загружено {total_rows} строк"))

    # ── Нормализация ──────────────────────────────────────────────────────────
    df = normalize_df(df)

    # ── Поля группировки ──────────────────────────────────────────────────────
    if args.sort_by:
        # Пользователь задал свои поля — используем их + BASE
        extra = [f for f in args.sort_by if f not in BASE_FIELDS]
        group_fields = BASE_FIELDS + extra
    else:
        group_fields = BASE_FIELDS

    # ── Шапка ─────────────────────────────────────────────────────────────────
    print_header(args.file, total_rows, group_fields, args.top)

    # ── Краткая статистика ────────────────────────────────────────────────────
    print_summary(df)

    # ── Основная таблица ──────────────────────────────────────────────────────
    print(c(Colors.BOLD, "🔍  ТОП ТРАФИКА (по количеству событий)"))
    print(c(Colors.GREY, "─" * 80))
    print(c(Colors.GREY,
        "  🥇 = #1 (самый частый)  🟢 = топ-3  "
        "Процент = от общего числа строк в логе\n"
    ))

    try:
        result, used_fields = analyze(df, group_fields, args.top)
    except ValueError as e:
        print(c(Colors.RED, f"  ❌ {e}"))
        sys.exit(1)

    print_table(result, used_fields, args.top, total_rows)

    # ── Рекомендации ──────────────────────────────────────────────────────────
    print()
    print(c(Colors.BOLD + Colors.MAGENTA, "💡  РЕКОМЕНДАЦИИ ДЛЯ ПРАВИЛ БЕЗОПАСНОСТИ"))
    print(c(Colors.GREY, "─" * 80))
    top3 = result.head(3)
    for _, row in top3.iterrows():
        parts = []
        if "srcAddr" in used_fields:
            parts.append(f"src={row.get('srcAddr','?')}")
        if "dstAddr" in used_fields:
            parts.append(f"dst={row.get('dstAddr','?')}")
        if "dstPort" in used_fields:
            parts.append(f"port={row.get('dstPort','?')}")
        if "ipProtocol" in used_fields:
            parts.append(f"proto={row.get('ipProtocol','?')}")
        if "app" in used_fields:
            parts.append(f"app={row.get('app','?')}")
        rule = row.get("securityRuleName", "?") if "securityRuleName" in used_fields else "?"
        cnt  = int(row["count"])
        print(c(Colors.YELLOW,
            f"  • [{cnt:,} событий] rule={rule} | {' | '.join(parts)}"
        ))
    print()

    # ── Экспорт ───────────────────────────────────────────────────────────────
    if args.export_json or args.export_csv:
        print(c(Colors.BOLD, "📤  ЭКСПОРТ"))
        print(c(Colors.GREY, "─" * 50))
        export_results(result, used_fields, args.export_json, args.export_csv, total_rows)
        print()

    print(c(Colors.BOLD + Colors.BLUE, "=" * 80))
    print(c(Colors.BOLD + Colors.BLUE, "  Анализ завершён."))
    print(c(Colors.BOLD + Colors.BLUE, "=" * 80))
    print()


if __name__ == "__main__":
    main()