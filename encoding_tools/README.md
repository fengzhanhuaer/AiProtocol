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

Use only [`encoding_safe_patch.py`](encoding_tools/encoding_safe_patch.py) for document add / delete / modify.
