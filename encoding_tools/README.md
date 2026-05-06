# encoding_tools

## [`encoding_safe_patch.py`](encoding_tools/encoding_safe_patch.py)

```bash
python encoding_tools/encoding_safe_patch.py run --config <patch.json> [options]
python encoding_tools/encoding_safe_patch.py rollback --report <apply-report.json>
```

Supported operations:

- `replace`
- `delete`
- `insert_before`
- `insert_after`
- `regex_replace`
- `line_replace`

## Rule

Use [`encoding_safe_patch.py`](encoding_tools/encoding_safe_patch.py) only for C/C++ source files (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hpp`). Other source files do not require this interface.
