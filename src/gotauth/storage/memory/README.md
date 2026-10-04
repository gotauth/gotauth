# gotauth.storage.memory

An in-memory `Adapter` (CONTRACTS section 3) for tests, examples and prototypes. Data is lost when the process ends.

```python
from gotauth.storage.memory import memory_adapter

adapter = memory_adapter()   # GotAuth(...) binds the merged schema
```

- Passes the shared conformance suite (`gotauth.testing.adapter_conformance`).
- Enforces `unique`, `unique_together` and references, including `on_delete` cascade, set_null and restrict (`ReferenceViolation`).
- Every operation and transaction holds one lock, so transactions are serialized and compare-and-set updates and single-use deletes are atomic.
- Rows are copied in and out; datetimes are stored as aware UTC.
- Inside a transaction, use the adapter that `transaction()` yields. Calling the root adapter from the task holding the transaction raises `RuntimeError` instead of deadlocking.
