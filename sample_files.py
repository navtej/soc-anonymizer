#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "openpyxl>=3.1",          # .xlsx / .xlsm
#     "python-calamine>=0.3",   # fast streamed reading of large .xlsx (Rust)
#     "rich>=13",               # progress display
# ]
# ///
"""
sample_files.py - make random samples of SOC exports (default 10% of records).

Supported (plain or .gz-compressed for the text formats):
  .csv .tsv .tab .psv        rows, header kept, delimiter auto-detected,
                             multi-line quoted cells handled
  .ndjson .jsonl .log .txt   one record per non-empty line
  .json                      array -> sample elements; object -> sample its
                             largest array (Azure {"value": [...]},
                             {"records": [...]}, Elastic {"hits": {"hits": [...]}} ...),
                             other keys kept; JSON-lines in a .json file detected
  .xlsx .xlsm                every sheet (incl. hidden): header row kept, non-empty
                             data rows sampled (.xlsm -> .xlsx, macros not copied).
                             Small books (sheet data <= --xlsx-full-max-mb, uncompressed):
                             formatting, comments, hyperlinks, widths, frozen panes
                             copied. Larger books: streamed row by row, values
                             only - formulas become their cached values.

Sampling is exact: ceil(N * percent / 100) records, at least --min-rows, at most
--max-rows, chosen uniformly at random and kept in their original order.
Each file gets its own RNG derived from --seed + its path, so results are
reproducible and independent of file order. No file is loaded into memory:
every format is streamed twice (count, then write the picked records).

Examples:
  uv run sample_files.py exports/*.csv exports/*.xlsx              # 10% -> ./samples/
  uv run sample_files.py exports/ -p 2.5 -o samples_2pct --seed 42 # whole folder, recursive
  uv run sample_files.py big_siem.ndjson.gz -p 1 --max-rows 5000

Writes sample_manifest.json (seed, percent, per-file counts) next to the samples.
Samples contain REAL data - treat them exactly like the originals.
"""
import argparse, csv, gzip, io, json, math, os, random, re, secrets, signal, sys, threading, time
from copy import copy
from pathlib import Path

from rich.console import Console
from rich.markup import escape

csv.field_size_limit(sys.maxsize)
CONSOLE = Console(stderr=True, highlight=False)
NAME_W = 36

DELIMITED = {".csv", ".tsv", ".tab", ".psv"}
LINES = {".ndjson", ".jsonl", ".log", ".txt"}
JSON = {".json"}
EXCEL = {".xlsx", ".xlsm"}
SUPPORTED = DELIMITED | LINES | JSON | EXCEL

def fit(name, w=NAME_W):
    return name.ljust(w) if len(name) <= w else name[: w - 13] + "…" + name[-12:]

def log(msg, style="dim"):
    CONSOLE.print(msg, style=style, markup=False)

# ---------- helpers ----------
def run_cancellable(fn, on_cancel):
    """Run fn() in a worker thread so Ctrl-C is handled at once, even while the
    worker is inside a long C call (openpyxl / gzip). The main thread
    only waits; on Ctrl-C it runs on_cancel() and hard-exits with 130. A second
    Ctrl-C during cleanup kills the process outright."""
    box = {}

    def target():
        try:
            box["ret"] = fn()
        except BaseException as e:
            box["exc"] = e

    t = threading.Thread(target=target, name="sample-worker", daemon=True)
    t.start()
    try:
        while t.is_alive():
            t.join(0.1)
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            on_cancel()
        finally:
            sys.stdout.flush(); sys.stderr.flush()
            os._exit(130)
    if "exc" in box:
        raise box["exc"]
    return box.get("ret")

def kind_of(path):
    """(format suffix, gzipped?) - 'x.csv.gz' -> ('.csv', True)."""
    sfx = [s.lower() for s in path.suffixes]
    gz = bool(sfx) and sfx[-1] == ".gz"
    base = sfx[-2] if gz and len(sfx) >= 2 else (sfx[-1] if sfx else "")
    return base, gz

def open_text(path, gz, mode="r", newline=None, encoding="utf-8-sig"):
    if gz:
        return io.TextIOWrapper(gzip.open(path, mode + "b"), encoding=encoding,
                                errors="replace", newline=newline)
    return open(path, mode, encoding=encoding, errors="replace", newline=newline)

def has_bom(path, gz):
    opener = gzip.open if gz else open
    with opener(path, "rb") as f:
        return f.read(3) == b"\xef\xbb\xbf"

class Sampler:
    def __init__(self, percent, min_rows, max_rows, seed):
        self.percent, self.min_rows, self.max_rows, self.seed = percent, min_rows, max_rows, seed

    def size(self, n):
        if n <= 0:
            return 0
        k = max(self.min_rows, math.ceil(n * self.percent / 100))
        if self.max_rows:
            k = min(k, self.max_rows)
        return min(k, n)

    def pick(self, n, key):
        """Sorted set of indices in range(n), deterministic per (seed, key)."""
        rng = random.Random(f"{self.seed}:{key}")
        return sorted(rng.sample(range(n), self.size(n)))

# ---------- progress ----------
class UI:
    def __init__(self, n_files, enabled=True):
        from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn,
                                   TextColumn, TimeElapsedColumn)
        from rich.table import Column
        self.progress = Progress(
            TextColumn("{task.description}", markup=False, table_column=Column(width=NAME_W, no_wrap=True)),
            BarColumn(bar_width=28), TaskProgressColumn(),
            MofNCompleteColumn(table_column=Column(justify="right", min_width=13)),
            TextColumn("{task.fields[unit]}", markup=False), TimeElapsedColumn(),
            console=CONSOLE, disable=not enabled, refresh_per_second=8)
        self.total = self.progress.add_task(fit("TOTAL"), total=n_files, unit="files")
        self.task, self.t0, self.n_ok, self.n_fail = None, 0.0, 0, 0

    def __enter__(self):
        self.progress.start(); return self

    def __exit__(self, *exc):
        self.progress.stop()

    def start(self, name, total, unit):
        self.t0 = time.monotonic()
        self.task = self.progress.add_task(fit(name), total=max(total, 1), unit=unit)

    def advance(self, n=1):
        self.progress.update(self.task, advance=n)

    def _close(self):
        if self.task is not None:
            self.progress.remove_task(self.task); self.task = None
        self.progress.advance(self.total)

    def _line(self, mark, style, name, detail):
        CONSOLE.print(f"[{style}]{mark}[/] {escape(fit(name))} {escape(detail)}")

    def done(self, name, kept, total, unit, note=""):
        self._close(); self.n_ok += 1
        pct = f"{100 * kept / total:5.1f}%" if total else "  n/a"
        self._line("✓", "green", name, f"{kept:>9,} / {total:<11,} {unit:<8} {pct} "
                                        f"{time.monotonic() - self.t0:6.1f}s  {note}".rstrip())

    def fail(self, name, why):
        self._close(); self.n_fail += 1
        self._line("✗", "red", name, why)

    def skip(self, name, why):
        self.progress.advance(self.total)
        self._line("–", "yellow", name, why)

def detect_delimiter(sample, suf):
    """Parse the first ~50 records with each candidate delimiter and keep the one
    giving a multi-column header and the most rows of the same width (more robust
    than csv.Sniffer on exports whose text cells are full of , ; and line breaks)."""
    import itertools
    default = {".tsv": "\t", ".tab": "\t", ".psv": "|"}.get(suf, ",")
    if suf != ".csv":
        return default
    best, best_score = default, None
    for d in (",", ";", "\t", "|"):
        try:
            rows = list(itertools.islice(csv.reader(io.StringIO(sample, newline=""), delimiter=d), 51))
        except csv.Error:
            continue
        if not rows or len(rows[0]) < 2:
            continue
        body = rows[1:-1] if len(rows) > 2 else rows[1:]
        same = sum(1 for r in body if len(r) == len(rows[0])) / max(len(body), 1)
        score = (round(same, 2), d == default, len(rows[0]))
        if best_score is None or score > best_score:
            best, best_score = d, score
    return best

# ---------- format handlers: each returns (kept, total, unit, note) ----------
def sample_delimited(src, dst, base, gz, sampler, key, ui):
    with open_text(src, gz, newline="") as f:
        head = f.read(65536)
    delim = detect_delimiter(head, base)
    with CONSOLE.status(f"counting rows in {src.name} ...", spinner="dots"):
        with open_text(src, gz, newline="") as f:
            n = sum(1 for _ in csv.reader(f, delimiter=delim)) - 1   # minus header
    n = max(n, 0)
    keep = set(sampler.pick(n, key))
    ui.start(src.name, n, "rows")
    enc = "utf-8-sig" if has_bom(src, gz) else "utf-8"
    eol = "\r\n" if "\r\n" in head else "\n"             # keep the source's line endings
    with open_text(src, gz, newline="") as f, open(dst, "w", newline="", encoding=enc) as out:
        r, w = csv.reader(f, delimiter=delim), csv.writer(out, delimiter=delim, lineterminator=eol)
        header = next(r, None)
        if header is not None:
            w.writerow(header)
        for i, row in enumerate(r):
            if i in keep:
                w.writerow(row)
            ui.advance()
    return len(keep), n, "rows", f"delimiter {delim!r}" if delim != "," else ""

def sample_lines(src, dst, gz, sampler, key, ui, unit="records"):
    with CONSOLE.status(f"counting lines in {src.name} ...", spinner="dots"):
        with open_text(src, gz) as f:
            n = sum(1 for line in f if line.strip())
    keep = set(sampler.pick(n, key))
    ui.start(src.name, n, unit)
    with open_text(src, gz) as f, open(dst, "w", encoding="utf-8") as out:
        i = 0
        for line in f:
            if not line.strip():
                continue
            if i in keep:
                out.write(line if line.endswith("\n") else line + "\n")
            i += 1
            ui.advance()
    return len(keep), n, unit, ""

_JSON_WS = re.compile(r"[ \t\n\r]*")

class JsonStream:
    """Pull parser for the outer levels of a JSON document read from a text stream.
    Objects and arrays are entered key by key / element by element; every other
    value (and every array element) is decoded on its own with raw_decode, so a
    multi-GB {"value": [...]} export never has to fit in memory."""

    def __init__(self, fh, chunk=1 << 20):
        self.fh, self.chunk, self.buf, self.pos, self.eof = fh, chunk, "", 0, False
        self.dec = json.JSONDecoder()

    def _more(self):
        # read at least as much as is buffered: a record larger than the chunk is
        # re-decoded O(log size) times instead of once per chunk
        data = self.fh.read(max(self.chunk, len(self.buf) - self.pos))
        self.buf, self.pos, self.eof = self.buf[self.pos:] + data, 0, not data
        return bool(data)

    def peek(self):
        """Next non-blank character, not consumed ('' at the end of the input)."""
        while True:
            self.pos = _JSON_WS.match(self.buf, self.pos).end()
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self._more():
                return ""

    def take(self, ch):
        c = self.peek()
        if c != ch:
            raise ValueError(f"invalid JSON: expected {ch!r}, found {c or 'end of file'!r}")
        self.pos += 1

    def value(self):
        self.peek()
        while True:
            try:
                v, end = self.dec.raw_decode(self.buf, self.pos)
                # a number may go on in the next chunk ('-0.5' + 'e-7'): need 3 chars after it
                if len(self.buf) - end >= 3 or self.eof:
                    self.pos = end
                    return v
            except json.JSONDecodeError as e:
                # a value cut off by the buffer fails at its end (or as an unterminated string)
                if self.eof or (e.pos < len(self.buf) - 8 and not e.msg.startswith("Unterminated")):
                    raise
            self._more()

    def elements(self):
        """Iterate an array; the caller consumes each element (value() or nested)."""
        self.take("[")
        if self.peek() == "]":
            self.pos += 1
            return
        while True:
            yield
            if self._close("]"):
                return

    def keys(self):
        """Iterate an object's keys; the caller consumes each value."""
        self.take("{")
        if self.peek() == "}":
            self.pos += 1
            return
        while True:
            k = self.value()
            self.take(":")
            yield k
            if self._close("}"):
                return

    def _close(self, end):
        c = self.peek()
        if c not in (",", end):
            raise ValueError(f"invalid JSON: expected ',' or {end!r}, found {c or 'end of file'!r}")
        self.pos += 1
        return c == end

    def finish(self):
        if self.peek():
            raise ValueError("invalid JSON: extra data after the document")

def json_dump_at(v, depth):
    """json.dumps(v, indent=2) as it reads nested `depth` levels deep, so streamed
    output is laid out exactly like a whole-document dump."""
    return json.dumps(v, ensure_ascii=False, indent=2).replace("\n", "\n" + "  " * depth)

def _largest_list(js, path=(), depth=0):
    """(length, path) of the largest array inside nested objects (not inside arrays),
    reading one element at a time."""
    c = js.peek()
    if c == "[":
        n = 0
        for _ in js.elements():
            js.value(); n += 1
        return n, path
    best = (-1, None)
    if c == "{" and depth < 5:
        for k in js.keys():
            cand = _largest_list(js, path + (k,), depth + 1)
            if cand[0] > best[0]:
                best = cand
    else:
        js.value()
    return best

COUNT_KEYS = ("count", "total", "@odata.count", "totalCount")

def _write_sampled(js, out, path, keep, ui, depth=0):
    """Copy the value under the reader to `out` (json.dumps indent=2 layout), one
    array element at a time. Down `path`, the array at its end keeps only the
    indices in `keep` and count fields next to it are set to the sample size."""
    ind = "\n" + "  " * (depth + 1)
    if js.peek() == "[" and not path:
        out.write("[")
        n = 0
        for i, _ in enumerate(js.elements()):
            v = js.value()
            if keep is None or i in keep:
                out.write(("," if n else "") + ind + json_dump_at(v, depth + 1)); n += 1
            if keep is not None:
                ui.advance()
        out.write("\n" + "  " * depth + "]" if n else "]")
    elif js.peek() == "{" and path:
        out.write("{")
        n = 0
        for k in js.keys():
            out.write(("," if n else "") + ind + json.dumps(k, ensure_ascii=False) + ": "); n += 1
            if k == path[0]:
                _write_sampled(js, out, path[1:], keep, ui, depth + 1)
            elif js.peek() == "[":
                _write_sampled(js, out, (), None, ui, depth + 1)      # other arrays: copied whole
            else:
                v = js.value()
                # keep obvious count fields consistent, e.g. {"count": 1234, "value": [...]}
                if len(path) == 1 and k in COUNT_KEYS and isinstance(v, int) and not isinstance(v, bool):
                    v = len(keep)
                out.write(json_dump_at(v, depth + 1))
        out.write("\n" + "  " * depth + "}" if n else "}")
    else:
        out.write(json_dump_at(js.value(), depth))

def sample_json(src, dst, gz, sampler, key, ui):
    try:
        with CONSOLE.status(f"counting records in {src.name} ...", spinner="dots"):
            with open_text(src, gz) as f:
                js = JsonStream(f)
                n, path = _largest_list(js)
                js.finish()
    except ValueError:                                   # JSON lines saved as .json
        return sample_lines(src, dst, gz, sampler, key, ui)
    with open_text(src, gz) as f, open(dst, "w", encoding="utf-8") as out:
        js = JsonStream(f)
        if path is None or n <= 0:
            ui.start(src.name, 1, "document")
            _write_sampled(js, out, None, None, ui)
            ui.advance()
            return 1, 1, "document", "no array found - copied whole"
        keep = set(sampler.pick(n, key))
        ui.start(src.name, n, "records")
        _write_sampled(js, out, path, keep, ui)
    note = f"array at {'.'.join(map(str, path))}" if path else ""
    return len(keep), n, "records", note

def _nonempty(values):
    return any(v not in (None, "") for v in values)

def xlsx_sheet_mb(path):
    """Uncompressed size of the sheet XML + shared strings: a good predictor of how
    slow / memory-hungry a full openpyxl load will be (also catches sheets whose
    formatting runs down to row 1,048,576, which the file size alone hides)."""
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            return sum(i.file_size for i in z.infolist()
                       if (i.filename.startswith("xl/worksheets/") and i.filename.endswith(".xml"))
                       or i.filename == "xl/sharedStrings.xml") / 1e6
    except zipfile.BadZipFile:
        return 0.0

XL_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
XL_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")

def xl_safe(v):
    """Excel stores control characters as _xHHHH_ escapes, which openpyxl leaves
    as they are: decode them, and replace the ones openpyxl refuses to write with
    U+FFFD (same values as the full-fidelity copy shows in Excel)."""
    if not isinstance(v, str):
        return v
    if "_x" in v:
        v = XL_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), v)
    return XL_ILLEGAL.sub("\ufffd", v)

CALAMINE_MAX_MB = 1000   # larger books are read by openpyxl read-only: ~10x slower, flat memory

def xlsx_stream(path):
    """Worksheets (incl. hidden ones, not chart sheets) as (title, hidden, rows) for
    streaming; rows are the non-empty rows as value lists ('' -> None, control
    characters made safe, formulas -> cached values), so rows that only carry
    formatting are skipped. calamine (Rust) parses ~10x faster than openpyxl but
    holds the sheet being read (about its XML size); books above CALAMINE_MAX_MB
    use openpyxl read-only."""
    if xlsx_sheet_mb(path) <= CALAMINE_MAX_MB:
        from python_calamine import CalamineWorkbook
        book = CalamineWorkbook.from_path(str(path))
        try:
            for m in book.sheets_metadata:
                if str(m.typ).endswith(".WorkSheet"):
                    sheet = book.get_sheet_by_name(m.name)
                    pad = [None] * sheet.start[1] if sheet.start else []  # iter_rows drops empty leading columns
                    rows = (pad + [None if v == "" else XL_ILLEGAL.sub("\ufffd", v) if isinstance(v, str) else v
                                   for v in row] for row in sheet.iter_rows())  # _xHHHH_ already decoded
                    yield m.name, not str(m.visible).endswith(".Visible"), filter(_nonempty, rows)
        finally:
            book.close()
        return
    from openpyxl import load_workbook
    book = load_workbook(path, read_only=True, data_only=True)
    try:
        for ws in book.worksheets:
            ws.reset_dimensions()                  # a wrong <dimension> would cut rows off
            rows = ([None if v == "" else xl_safe(v) for v in row] for row in ws.iter_rows(values_only=True))
            yield ws.title, ws.sheet_state != "visible", filter(_nonempty, rows)
    finally:
        book.close()

def sample_xlsx(src, dst, sampler, key, ui, full_max_mb):
    """Full-fidelity copy only for books whose sheet data is small enough to load
    quickly; everything else is streamed."""
    data_mb = xlsx_sheet_mb(src)
    if data_mb <= full_max_mb:
        return sample_xlsx_full(src, dst, sampler, key, ui)
    return sample_xlsx_fast(src, dst, sampler, key, ui, data_mb)

def _xlsx_dst(src, dst):
    return dst.with_suffix(".xlsx") if dst.suffix.lower() == ".xlsm" else dst

def sample_xlsx_fast(src, dst, sampler, key, ui, size_mb):
    """Large books: xlsx_stream reads each sheet twice (count the non-empty rows,
    then pick), write-only mode spools the sample to disk, so memory stays bounded
    however large the book is. Values only."""
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font
    bold = Font(bold=True)
    plans, total = [], 0
    with CONSOLE.status(f"counting rows in {src.name} ({size_mb:,.0f} MB of sheet data) ...",
                        spinner="dots") as st:
        for title, _hidden, rows in xlsx_stream(src):
            st.update(f"counting rows in {src.name} ({size_mb:,.0f} MB of sheet data) › sheet '{title}' ...")
            n = max(sum(1 for _ in rows) - 1, 0)        # minus header
            plans.append(set(sampler.pick(n, f"{key}#{title}")))
            total += n
    ui.start(src.name, total, "rows")
    out, kept = Workbook(write_only=True), 0
    for keep, (title, hidden, rows) in zip(plans, xlsx_stream(src)):
        nws = out.create_sheet(title)
        if hidden:                                     # hidden / veryHidden
            nws.sheet_state = "hidden"
        header = next(rows, None)
        if header is not None:
            cells = []
            for v in header:
                c = WriteOnlyCell(nws, value=v); c.font = bold; cells.append(c)
            nws.append(cells)
        for i, row in enumerate(rows):
            if i in keep:
                nws.append(row)
            ui.advance()
        kept += len(keep)
    out.save(_xlsx_dst(src, dst))
    note = f"{len(plans)} sheet(s), {size_mb:,.0f} MB streamed: values only"
    if src.suffix.lower() == ".xlsm":
        note += ", -> .xlsx"
    return kept, total, "rows", note

def _last_row(ws):
    """Last row holding a real value - ignores cells that only carry formatting."""
    rows = [r for (r, _c), cell in ws._cells.items() if cell.value not in (None, "")]
    return max(rows) if rows else 0

def sample_xlsx_full(src, dst, sampler, key, ui):
    from openpyxl import Workbook, load_workbook
    from openpyxl.comments import Comment
    with CONSOLE.status(f"opening {src.name} ...", spinner="dots"):
        wb = load_workbook(src)                           # formulas kept as written
    out = Workbook(); out.remove(out.active)
    plans, total = [], 0
    for ws in wb.worksheets:
        last = _last_row(ws)
        rows = list(ws.iter_rows(max_row=last)) if last else []
        h = next((i for i, r in enumerate(rows) if _nonempty(c.value for c in r)), None)
        data = [r for r in rows[h + 1:] if _nonempty(c.value for c in r)] if h is not None else []
        plans.append((ws, rows[: h + 1] if h is not None else [], data,
                      sampler.pick(len(data), f"{key}#{ws.title}")))
        total += len(data)
    ui.start(src.name, total, "rows")
    kept = 0
    for ws, head, data, idx in plans:
        nws = out.create_sheet(ws.title)
        nws.sheet_state = ws.sheet_state
        for col, dim in ws.column_dimensions.items():
            if dim.width:
                nws.column_dimensions[col].width = dim.width
        if ws.freeze_panes:
            nws.freeze_panes = ws.freeze_panes
        if ws.auto_filter and ws.auto_filter.ref:
            nws.auto_filter.ref = ws.auto_filter.ref.split(":")[0] + ":" + \
                ws.auto_filter.ref.split(":")[-1].rstrip("0123456789") + str(len(head) + len(idx))
        for r_out, row in enumerate(head + [data[i] for i in idx], start=1):
            for c in row:
                if not hasattr(c, "column") or (c.value is None and not c.has_style):
                    continue
                nc = nws.cell(row=r_out, column=c.column, value=xl_safe(c.value))
                if c.has_style:
                    nc.font, nc.fill, nc.border = copy(c.font), copy(c.fill), copy(c.border)
                    nc.alignment, nc.protection = copy(c.alignment), copy(c.protection)
                    nc.number_format = c.number_format
                if c.comment:
                    nc.comment = Comment(c.comment.text, c.comment.author)
                if c.hyperlink and c.hyperlink.target:
                    nc.hyperlink = c.hyperlink.target
        ui.advance(len(data))
        kept += len(idx)
    out.save(_xlsx_dst(src, dst))                         # .xlsm -> .xlsx, macros not copied
    note = f"{len(plans)} sheet(s)" + (" -> .xlsx, macros dropped" if src.suffix.lower() == ".xlsm" else "")
    return kept, total, "rows", note

# ---------- driver ----------
def collect(inputs, recursive=True):
    """[(file, relative output path)] - folders are walked, structure mirrored."""
    found = []
    for p in inputs:
        if p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            for f in sorted(it):
                if f.is_file() and not f.name.startswith(".") and kind_of(f)[0] in SUPPORTED | {".xls"}:
                    found.append((f, f.relative_to(p)))
        elif p.is_file():
            found.append((p, Path(p.name)))
        else:
            log(f"– not found, skipped: {p}", style="yellow")
    return found

def out_path(outdir, rel):
    base, gz = kind_of(rel)
    name = rel.name[: -len(".gz")] if gz else rel.name             # samples are written uncompressed
    return outdir / rel.parent / name

def process(src, dst, sampler, ui, full_max_mb=25.0):
    base, gz = kind_of(src)
    key = str(src.resolve())
    if base == ".xls":
        return ui.skip(src.name, "legacy .xls not supported - re-save as .xlsx")
    if base not in SUPPORTED:
        return ui.skip(src.name, f"unsupported type '{base or src.suffix}'")
    if dst.resolve() == src.resolve():
        raise ValueError("output would overwrite the input - choose another --outdir")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if base in DELIMITED:
        res = sample_delimited(src, dst, base, gz, sampler, key, ui)
    elif base in LINES:
        res = sample_lines(src, dst, gz, sampler, key, ui,
                           "lines" if base in {".log", ".txt"} else "records")
    elif base in JSON:
        res = sample_json(src, dst, gz, sampler, key, ui)
    elif gz:
        return ui.skip(src.name, "gzipped Excel is not supported")
    else:
        res = sample_xlsx(src, dst, sampler, key, ui, full_max_mb)
    ui.done(src.name, *res)
    return res

def percent_arg(v):
    p = float(v)
    if not 0 < p <= 100:
        raise argparse.ArgumentTypeError("percent must be in (0, 100]")
    return p

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", type=Path, help="files and/or folders (folders are walked)")
    ap.add_argument("-p", "--percent", type=percent_arg, default=10.0,
                    help="share of records to keep, 0-100 (default: 10)")
    ap.add_argument("-o", "--outdir", type=Path, default=Path("samples"), help="default: ./samples")
    ap.add_argument("--seed", help="random seed for reproducible samples (default: random, printed)")
    ap.add_argument("--min-rows", type=int, default=1,
                    help="keep at least this many records per file/sheet (default: 1)")
    ap.add_argument("--max-rows", type=int, help="keep at most this many records per file/sheet")
    ap.add_argument("--xlsx-full-max-mb", type=float, default=25.0,
                    help="workbooks whose uncompressed sheet data is up to this size keep formatting/"
                         "comments/links; larger ones use fast values-only mode (default: 25)")
    ap.add_argument("--no-recursive", action="store_true", help="don't descend into sub-folders")
    ap.add_argument("--no-progress", action="store_true", help="plain output, no progress bars")
    ap.add_argument("--verbose", action="store_true", help="full tracebacks on errors")
    a = ap.parse_args()

    seed = a.seed or secrets.token_hex(4)
    sampler = Sampler(a.percent, a.min_rows, a.max_rows, seed)
    files = collect(a.inputs, recursive=not a.no_recursive)
    if not files:
        sys.exit("no input files found")
    od = a.outdir.resolve()
    src_dirs = {p.resolve() if p.is_dir() else p.resolve().parent for p in a.inputs if p.exists()}
    if od in src_dirs or any(d in od.parents for d in src_dirs if any(p.is_dir() for p in a.inputs)):
        sys.exit(f"--outdir {a.outdir} is (inside) an input folder - pick a separate folder "
                 "so originals are never overwritten or re-sampled")
    log(f"sampling {a.percent:g}% with seed {seed}  (re-run with --seed {seed} to reproduce)")
    a.outdir.mkdir(parents=True, exist_ok=True)
    manifest = {"seed": seed, "percent": a.percent, "min_rows": a.min_rows,
                "max_rows": a.max_rows, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "files": []}
    state = {"ui": None, "current": None, "started": time.monotonic()}
    manifest_path = a.outdir / "sample_manifest.json"

    def run():
        with UI(len(files), enabled=not a.no_progress) as ui:
            state["ui"] = ui
            for src, rel in files:
                dst = out_path(a.outdir, rel)
                try:
                    state["current"] = dst
                    res = process(src, dst, sampler, ui, a.xlsx_full_max_mb)
                    state["current"] = None
                    if res:
                        kept, total, unit, note = res
                        manifest["files"].append({"source": str(src), "sample": str(dst), "unit": unit,
                                                  "total": total, "kept": kept, "note": note})
                except Exception as e:
                    state["current"] = None
                    if a.verbose:
                        raise
                    ui.fail(src.name, f"{type(e).__name__}: {e}"[:200])
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        log(f"{ui.n_ok} file(s) sampled, {ui.n_fail} failed -> {a.outdir}/  "
            f"({time.monotonic() - state['started']:.1f}s)  seed {seed}",
            style="bold green" if not ui.n_fail else "bold red")
        log("samples contain real data - handle them like the originals", style="yellow")
        return 1 if ui.n_fail else 0

    def on_cancel():
        ui = state["ui"]
        if ui is not None:
            try:
                ui.progress.stop()
            except Exception:
                pass
        CONSOLE.show_cursor(True)
        cur = state["current"]
        if cur is not None:                               # half-written sample: remove it
            for c in {cur, _xlsx_dst(cur, cur)}:
                try:
                    c.unlink(missing_ok=True)
                except OSError:
                    pass
        manifest["cancelled"] = True
        try:
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        except OSError:
            pass
        log(f"cancelled - {len(manifest['files'])} file(s) completed in {a.outdir}/"
            f"{', partial output of the current file removed' if cur is not None else ''}"
            f" ({time.monotonic() - state['started']:.1f}s)  seed {seed}", style="bold yellow")

    sys.exit(run_cancellable(run, on_cancel))

if __name__ == "__main__":
    main()
