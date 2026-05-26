#!/usr/bin/env python3
"""
NGFW Log Analyzer
=================
Анализирует логи NGFW в форматах CSV или JSON.
Показывает топ-трафик по ключевым полям для написания правил безопасности.

Использование:
  python3 ngfw_analyzer.py <файл.csv или файл.json> [опции]

Опции:
  --sort-by FIELD [FIELD ...]   Дополнительные поля группировки
  --top N                       Показать топ N записей (по умолчанию: 20)
  --export-json FILE            Экспорт результатов в JSON
  --export-csv FILE             Экспорт результатов в CSV
  --min-rows N                  Минимум строк для анализа (по умолчанию: 30)
  --no-color                    Отключить цветной вывод

Фильтры строк (можно совмещать, объединяются по AND):
  --srcip   PATTERN    Фильтр по srcAddr
  --dstip   PATTERN    Фильтр по dstAddr
  --port    PATTERN    Фильтр по dstPort
  --proto   PATTERN    Фильтр по ipProtocol
  --app     PATTERN    Фильтр по app
  --rule    PATTERN    Фильтр по securityRuleName
  --action  PATTERN    Фильтр по action

  PATTERN поддерживает:
    - точное значение:    --srcip=10.0.0.1
    - wildcard (*):       --srcip=10.0.0.*  --app=*http*
    - список через ,:     --port=80,443,8080
    - диапазон:           --port=1024-65535

Режимы анализа (оба запускаются всегда):
  [1] Базовый   — srcAddr, dstAddr, dstPort, ipProtocol, securityRuleName
  [2] По action — srcAddr, dstAddr, dstPort, ipProtocol, action, securityRuleName

Дополнительные поля через --sort-by (добавляются к обоим режимам):
  app, deviceName, contextName, srcZoneName, dstZoneName

В каждой строке результата есть поле new_rule — предложение имени нового правила.
Значения Count ≥1K отображаются как 23K / 3.1M / 1.2B.

Примеры:
  python3 ngfw_analyzer.py logs.csv
  python3 ngfw_analyzer.py logs.csv --sort-by app srcZoneName dstZoneName
  python3 ngfw_analyzer.py logs.csv --srcip=10.0.0.* --port=80,443
  python3 ngfw_analyzer.py logs.csv --dstip=8.8.8.8 --proto=UDP --sort-by app
  python3 ngfw_analyzer.py logs.csv --port=1024-65535 --action=allow --top 30
  python3 ngfw_analyzer.py logs.json --export-json result.json --export-csv result.csv
"""

import argparse
import json
import re
import sys
import os
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

USE_COLOR = True

def c(color: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{Colors.RESET}"

# ─── Константы ────────────────────────────────────────────────────────────────

# Базовый анализ (без app — она идёт в расширенный через --sort-by)
BASE_FIELDS         = ["srcAddr", "dstAddr", "dstPort", "ipProtocol", "securityRuleName"]
# Второй обязательный блок — тот же + action
BASE_ACTION_FIELDS  = ["srcAddr", "dstAddr", "dstPort", "ipProtocol", "action", "securityRuleName"]

# Поля, разрешённые через --sort-by
EXTRA_FIELDS_ALLOWED = [
    "app", "deviceName", "contextName", "srcZoneName", "dstZoneName",
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
    "action":           "Action",
    "app":              "Application",
    "securityRuleName": "Security Rule",
    "deviceName":       "Device",
    "contextName":      "Context",
    "srcZoneName":      "Src Zone",
    "dstZoneName":      "Dst Zone",
    "new_rule":         "Suggested New Rule",
}

# ─── Загрузка данных ──────────────────────────────────────────────────────────

def detect_csv_separator(path: str) -> str:
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
    df = df.copy()
    df.columns = [col.strip() for col in df.columns]
    if "ipProtocol" in df.columns:
        df["ipProtocol"] = df["ipProtocol"].astype(str).apply(
            lambda x: PROTO_MAP.get(x.strip(), x.strip())
        )
    df = df.fillna("—")
    df = df.replace(r"^\s*$", "—", regex=True)
    return df

# ─── Генерация new_rule ───────────────────────────────────────────────────────

def _slugify(val: str, max_len: int = 20) -> str:
    """Превращает значение поля в безопасный фрагмент имени правила."""
    val = str(val).strip()
    val = re.sub(r"[^\w.\-]", "_", val)   # заменяем спецсимволы
    val = re.sub(r"_+", "_", val)         # схлопываем подряд идущие _
    val = val.strip("_")
    return val[:max_len] if val else "any"

def build_new_rule(row: pd.Series, used_fields: list[str]) -> str:
    """
    Строит имя предлагаемого правила вида:
      new_rule_<proto>_<srcIP|srcZone>_to_<dstIP|dstZone>_<port>[_<action>][_<app>]
    """
    parts = ["new_rule"]

    # protocol
    proto = _slugify(row.get("ipProtocol", "any")) if "ipProtocol" in used_fields else "any"
    parts.append(proto)

    # source: предпочитаем зону, иначе IP
    if "srcZoneName" in used_fields:
        src = _slugify(row.get("srcZoneName", "any"))
    elif "srcAddr" in used_fields:
        src = _slugify(row.get("srcAddr", "any"))
    else:
        src = "any"
    parts.append(src)

    parts.append("to")

    # destination: зона → IP → any
    if "dstZoneName" in used_fields:
        dst = _slugify(row.get("dstZoneName", "any"))
    elif "dstAddr" in used_fields:
        dst = _slugify(row.get("dstAddr", "any"))
    else:
        dst = "any"
    parts.append(dst)

    # port
    if "dstPort" in used_fields:
        port = _slugify(row.get("dstPort", "any"))
        parts.append(f"p{port}")

    # action (если есть в полях)
    if "action" in used_fields:
        action = _slugify(row.get("action", "")).upper()
        if action and action != "—":
            parts.append(action)

    # app (если есть в полях)
    if "app" in used_fields:
        app = _slugify(row.get("app", ""))
        if app and app not in ("—", "unknown", "any"):
            parts.append(app)

    return "_".join(parts)

# ─── Фильтрация строк ────────────────────────────────────────────────────────

def _match_filter(value: str, pattern: str) -> bool:
    """
    Совпадение значения с паттерном фильтра.
    Поддерживает:
      - точное совпадение:        10.0.0.1
      - wildcard *:               10.0.0.*  или  *allow*
      - несколько через запятую:  80,443,8080
      - диапазон портов:          1024-65535
    """
    value = str(value).strip().lower()
    for pat in pattern.split(","):
        pat = pat.strip().lower()
        # диапазон числовых значений (порты)
        if re.match(r"^\d+-\d+$", pat):
            lo, hi = pat.split("-")
            try:
                if int(lo) <= int(value) <= int(hi):
                    return True
                continue
            except ValueError:
                pass
        # wildcard через fnmatch
        import fnmatch
        if fnmatch.fnmatch(value, pat):
            return True
    return False

def apply_filters(df: pd.DataFrame, filters: dict[str, str]) -> pd.DataFrame:
    """
    Применяет фильтры к DataFrame.
    filters = {"srcAddr": "10.0.0.*", "dstPort": "80,443", ...}
    Все условия объединяются через AND.
    Возвращает отфильтрованный DataFrame и список активных фильтров для вывода.
    """
    active = []
    for field, pattern in filters.items():
        if not pattern:
            continue
        if field not in df.columns:
            print(c(Colors.YELLOW,
                f"  ⚠  Поле «{field}» не найдено в данных — фильтр пропущен"))
            continue
        mask = df[field].apply(lambda v: _match_filter(str(v), pattern))
        df = df[mask]
        active.append(f"{field}={pattern}")
    return df, active



def analyze(df: pd.DataFrame, group_fields: list[str], top_n: int):
    """Группирует, считает, добавляет new_rule."""
    existing = [f for f in group_fields if f in df.columns]
    missing  = [f for f in group_fields if f not in df.columns]
    if missing:
        print(c(Colors.YELLOW,
            f"  ⚠  Поля не найдены в файле и пропущены: {', '.join(missing)}"))
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
    # Добавляем new_rule
    grouped["new_rule"] = grouped.apply(
        lambda row: build_new_rule(row, existing), axis=1
    )
    grouped.index = grouped.index + 1
    return grouped, existing

# ─── Отображение ──────────────────────────────────────────────────────────────

def bar(count: int, max_count: int, width: int = 28) -> str:
    if max_count == 0:
        return ""
    filled = int(round(count / max_count * width))
    return "█" * filled + "░" * (width - filled)

def fmt_count(n: int) -> str:
    """Форматирует число: <1K → число, ≥1K → 23K, ≥1M → 3.1M, ≥1B → 1.2B."""
    if n >= 1_000_000_000:
        return f"{n/1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)

def col_width(series: pd.Series, header: str, max_w: int = 38) -> int:
    max_val = series.astype(str).str.len().max()
    return min(max(int(max_val), len(header)) + 2, max_w)

def print_table(result: pd.DataFrame, fields: list[str], total_rows: int):
    if result.empty:
        print(c(Colors.YELLOW, "  Нет данных для отображения."))
        return

    display_fields = fields  # new_rule только в рекомендациях, не в таблице
    max_count = result["count"].max()
    headers   = ["#"] + [FIELD_LABELS.get(f, f) for f in display_fields] + ["Count", "Bar"]

    widths = [4]
    for f in display_fields:
        widths.append(col_width(result[f], FIELD_LABELS.get(f, f)))
    widths += [18, 30]

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
        cnt   = row["count"]
        pct   = cnt / total_rows * 100
        b     = bar(cnt, max_count)
        cnt_str = f"{fmt_count(cnt)} ({pct:.1f}%)"
        cells = (
            [str(i)]
            + [str(row[f]) for f in display_fields]
            + [cnt_str, b]
        )
        if i == 1:
            color = Colors.YELLOW
        elif i <= 3:
            color = Colors.GREEN
        else:
            color = None
        print(row_str(cells, color))

    print(c(Colors.CYAN, bot_line))

# ─── Экспорт ──────────────────────────────────────────────────────────────────

def export_results(
    basic_result: pd.DataFrame,   basic_fields: list[str],
    action_result: pd.DataFrame,  action_fields: list[str],
    json_path: str | None,
    csv_path: str | None,
    total_rows: int,
):
    def prep(df: pd.DataFrame) -> pd.DataFrame:
        out = df.copy()
        out.insert(0, "rank", range(1, len(df) + 1))
        out["percent"] = (out["count"] / total_rows * 100).round(2)
        return out

    basic_exp  = prep(basic_result)
    action_exp = prep(action_result)

    if json_path:
        meta = {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "total_log_rows": total_rows,
            "basic_analysis": {
                "group_fields": basic_fields + ["new_rule"],
                "results": basic_exp.to_dict(orient="records"),
            },
            "action_analysis": {
                "group_fields": action_fields + ["new_rule"],
                "results": action_exp.to_dict(orient="records"),
            },
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        print(c(Colors.GREEN, f"  ✓  JSON экспорт: {json_path}"))

    if csv_path:
        # два листа в одном CSV через разделитель-комментарий
        base_csv   = os.path.splitext(csv_path)[0]
        ext_csv    = os.path.splitext(csv_path)[1] or ".csv"
        basic_path  = f"{base_csv}_basic{ext_csv}"
        action_path = f"{base_csv}_action{ext_csv}"
        basic_exp.to_csv(basic_path,  index=False, encoding="utf-8-sig")
        action_exp.to_csv(action_path, index=False, encoding="utf-8-sig")
        print(c(Colors.GREEN, f"  ✓  CSV базовый  : {basic_path}"))
        print(c(Colors.GREEN, f"  ✓  CSV по action: {action_path}"))

# ─── Шапка / Статистика ───────────────────────────────────────────────────────

def print_header(path: str, total: int, filtered: int, extra: list[str],
                 top_n: int, active_filters: list[str]):
    w = 90
    print()
    print(c(Colors.BOLD + Colors.BLUE, "=" * w))
    print(c(Colors.BOLD + Colors.BLUE,
        "  NGFW LOG ANALYZER — Анализ трафика для выработки правил безопасности"))
    print(c(Colors.BOLD + Colors.BLUE, "=" * w))
    print(c(Colors.GREY, f"  Файл          : {path}"))
    if filtered < total:
        print(c(Colors.GREY,  f"  Строк (всего) : {total}"))
        print(c(Colors.YELLOW, f"  Строк (фильтр): {filtered}  [{total-filtered} отброшено]"))
    else:
        print(c(Colors.GREY, f"  Строк          : {total}"))
    if active_filters:
        print(c(Colors.CYAN,  f"  Фильтры        : {' AND '.join(active_filters)}"))
    print(c(Colors.GREY, f"  Доп. поля      : {', '.join(extra) if extra else '—'}"))
    print(c(Colors.GREY, f"  Топ            : {top_n}"))
    print(c(Colors.GREY,
        f"  Время          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"))
    print(c(Colors.BOLD + Colors.BLUE, "=" * w))
    print()

def print_summary(df: pd.DataFrame):
    print(c(Colors.BOLD, "\n📊  ОБЩАЯ СТАТИСТИКА"))
    print(c(Colors.GREY, "─" * 55))

    if "action" in df.columns:
        actions = df["action"].value_counts()
        for act, cnt in actions.items():
            icon = "✅" if str(act).lower() == "allow" else "🚫"
            print(f"  {icon} {str(act).upper():12s}: {cnt:>6} событий")

    if "ipProtocol" in df.columns:
        protos = df["ipProtocol"].value_counts().head(5)
        print(c(Colors.GREY, "\n  Протоколы (топ-5):"))
        for p, cnt in protos.items():
            print(f"    {str(p):10s}: {cnt}")

    if "app" in df.columns:
        apps = df["app"].value_counts().head(5)
        print(c(Colors.GREY, "\n  Приложения (топ-5):"))
        for a, cnt in apps.items():
            print(f"    {str(a):22s}: {cnt}")
    print()

def print_recommendations(result: pd.DataFrame, used_fields: list[str]):
    print()
    print(c(Colors.BOLD + Colors.MAGENTA,
        "💡  РЕКОМЕНДАЦИИ ДЛЯ ПРАВИЛ БЕЗОПАСНОСТИ (топ-3)"))
    print(c(Colors.GREY, "─" * 90))
    for _, row in result.head(3).iterrows():
        parts = []
        for f in ["srcAddr", "dstAddr", "dstPort", "ipProtocol", "action", "app"]:
            if f in used_fields:
                lbl = FIELD_LABELS.get(f, f)
                parts.append(f"{lbl}={row.get(f,'?')}")
        rule     = row.get("securityRuleName", "?") if "securityRuleName" in used_fields else "?"
        cnt      = row["count"]
        new_rule = row.get("new_rule", "")
        print(c(Colors.YELLOW,
            f"  • [{cnt:>5} событий] existing_rule={rule}"))
        print(c(Colors.WHITE,
            f"    {' | '.join(parts)}"))
        print(c(Colors.CYAN,
            f"    → {new_rule}"))
        print()

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Анализатор логов NGFW (CSV/JSON) для выработки правил безопасности",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file", help="Путь к файлу лога (.csv или .json)")
    parser.add_argument(
        "--sort-by", nargs="+", metavar="FIELD",
        help=(
            "Дополнительные поля группировки (добавляются к обоим блокам анализа). "
            f"Доступные: {', '.join(EXTRA_FIELDS_ALLOWED)}"
        ),
    )
    parser.add_argument("--top", type=int, default=20, metavar="N",
                        help="Показать топ N записей (по умолчанию: 20)")
    parser.add_argument("--export-json", metavar="FILE",
                        help="Экспортировать результаты в JSON")
    parser.add_argument("--export-csv",  metavar="FILE",
                        help="Экспортировать результаты в CSV (два файла: _basic и _action)")
    parser.add_argument("--min-rows", type=int, default=30, metavar="N",
                        help="Минимальное кол-во строк для анализа (по умолчанию: 30)")
    parser.add_argument("--no-color", action="store_true",
                        help="Отключить цветной вывод")

    # ── Фильтры по полям ──────────────────────────────────────────────────────
    flt = parser.add_argument_group(
        "фильтры (сужают анализируемые строки, можно совмещать)",
        "Поддерживают wildcard (*), список через запятую, диапазон (напр. 1024-65535)"
    )
    flt.add_argument("--srcip",   metavar="PATTERN",
                     help="Фильтр по srcAddr.  Пример: --srcip=10.0.0.*")
    flt.add_argument("--dstip",   metavar="PATTERN",
                     help="Фильтр по dstAddr.  Пример: --dstip=192.168.1.5")
    flt.add_argument("--port",    metavar="PATTERN",
                     help="Фильтр по dstPort.  Пример: --port=80,443  или  --port=1024-65535")
    flt.add_argument("--proto",   metavar="PATTERN",
                     help="Фильтр по ipProtocol. Пример: --proto=TCP")
    flt.add_argument("--app",     metavar="PATTERN",
                     help="Фильтр по app.       Пример: --app=*http*")
    flt.add_argument("--rule",    metavar="PATTERN",
                     help="Фильтр по securityRuleName. Пример: --rule=*deny*")
    flt.add_argument("--action",  metavar="PATTERN",
                     help="Фильтр по action.    Пример: --action=allow")

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

    if total_rows <= args.min_rows:
        print(c(Colors.YELLOW,
            f"  ⚠  Файл содержит {total_rows} строк — ниже порога {args.min_rows}.\n"
            f"     Анализ может быть ненадёжным. "
            f"Используйте --min-rows N чтобы изменить порог."))
        if total_rows == 0:
            print(c(Colors.RED, "  ❌ Файл пуст. Завершение."))
            sys.exit(1)
    else:
        print(c(Colors.GREEN, f"  ✓  Загружено {total_rows} строк"))

    df = normalize_df(df)

    # ── Применяем фильтры ─────────────────────────────────────────────────────
    filter_map = {
        "srcAddr":          args.srcip,
        "dstAddr":          args.dstip,
        "dstPort":          args.port,
        "ipProtocol":       args.proto,
        "app":              args.app,
        "securityRuleName": args.rule,
        "action":           args.action,
    }
    df, active_filters = apply_filters(df, {k: v for k, v in filter_map.items() if v})
    filtered_rows = len(df)

    if filtered_rows == 0:
        print(c(Colors.RED,
            "  ❌ После применения фильтров строк не осталось. "
            "Проверьте параметры фильтрации."))
        sys.exit(1)
    elif active_filters:
        print(c(Colors.GREEN,
            f"  ✓  После фильтрации: {filtered_rows} строк "
            f"({total_rows - filtered_rows} отброшено)"))

    # ── Дополнительные поля ───────────────────────────────────────────────────
    extra = []
    if args.sort_by:
        for f in args.sort_by:
            if f not in BASE_FIELDS and f not in BASE_ACTION_FIELDS and f not in extra:
                extra.append(f)

    basic_fields  = BASE_FIELDS       + extra
    action_fields = BASE_ACTION_FIELDS + extra

    print_header(args.file, total_rows, filtered_rows, extra, args.top, active_filters)
    print_summary(df)

    # ═══════════════════════════════════════════════════════════════════════════
    #  БЛОК 1 — Базовый анализ
    # ═══════════════════════════════════════════════════════════════════════════
    print(c(Colors.BOLD + Colors.WHITE,
        "┌─────────────────────────────────────────────────────────────────────────────┐"))
    print(c(Colors.BOLD + Colors.WHITE,
        "│  [1] БАЗОВЫЙ АНАЛИЗ                                                         │"))
    print(c(Colors.BOLD + Colors.WHITE,
        "│      srcAddr · dstAddr · dstPort · ipProtocol · securityRuleName            │"))
    print(c(Colors.BOLD + Colors.WHITE,
        "└─────────────────────────────────────────────────────────────────────────────┘"))
    print(c(Colors.GREY,
        "  🥇 = #1  🟢 = топ-3  Процент = от общего числа строк в логе\n"))

    try:
        basic_result, basic_used = analyze(df, basic_fields, args.top)
    except ValueError as e:
        print(c(Colors.RED, f"  ❌ {e}"))
        sys.exit(1)

    print_table(basic_result, basic_used, total_rows)
    print_recommendations(basic_result, basic_used)

    # ═══════════════════════════════════════════════════════════════════════════
    #  БЛОК 2 — Анализ с action
    # ═══════════════════════════════════════════════════════════════════════════
    print(c(Colors.BOLD + Colors.WHITE,
        "┌─────────────────────────────────────────────────────────────────────────────┐"))
    print(c(Colors.BOLD + Colors.WHITE,
        "│  [2] АНАЛИЗ С ДЕЙСТВИЕМ (action)                                            │"))
    print(c(Colors.BOLD + Colors.WHITE,
        "│      srcAddr · dstAddr · dstPort · ipProtocol · action · securityRuleName   │"))
    print(c(Colors.BOLD + Colors.WHITE,
        "└─────────────────────────────────────────────────────────────────────────────┘"))
    print(c(Colors.GREY,
        "  🥇 = #1  🟢 = топ-3  Процент = от общего числа строк в логе\n"))

    try:
        action_result, action_used = analyze(df, action_fields, args.top)
    except ValueError as e:
        print(c(Colors.RED, f"  ❌ {e}"))
        sys.exit(1)

    print_table(action_result, action_used, total_rows)
    print_recommendations(action_result, action_used)

    # ── Экспорт ───────────────────────────────────────────────────────────────
    if args.export_json or args.export_csv:
        print(c(Colors.BOLD, "📤  ЭКСПОРТ"))
        print(c(Colors.GREY, "─" * 55))
        export_results(
            basic_result,  basic_used,
            action_result, action_used,
            args.export_json, args.export_csv,
            total_rows,
        )
        print()

    print(c(Colors.BOLD + Colors.BLUE, "=" * 90))
    print(c(Colors.BOLD + Colors.BLUE, "  Анализ завершён."))
    print(c(Colors.BOLD + Colors.BLUE, "=" * 90))
    print()


if __name__ == "__main__":
    main()