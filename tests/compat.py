"""
Pytest and Unittest compatibility helper for RansomShield test suite.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any, Type


@contextlib.contextmanager
def assert_raises(exc_type: Type[Exception], match: str | None = None):
    """Context manager replacing pytest.raises using standard library."""
    try:
        yield
    except exc_type as exc:
        if match is not None:
            pattern = re.compile(match)
            if not pattern.search(str(exc)):
                raise AssertionError(
                    f"Exception message '{exc}' does not match pattern '{match}'"
                ) from exc
    else:
        raise AssertionError(f"Expected exception {exc_type.__name__} was not raised.")
