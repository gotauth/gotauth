"""In-memory storage adapter for tests, examples and quick starts.

```python
from gotauth.storage.memory import memory_adapter

adapter = memory_adapter()  # GotAuth(database=adapter, ...) binds the schema
```
"""

from __future__ import annotations

from gotauth.storage.memory._adapter import MemoryAdapter, memory_adapter

__all__ = ["MemoryAdapter", "memory_adapter"]
