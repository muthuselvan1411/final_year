#!/usr/bin/env python3
"""Run the read-only RansomShield dashboard API."""

from __future__ import annotations

import uvicorn


if __name__ == "__main__":
    uvicorn.run("dashboard.api:app", host="127.0.0.1", port=8000, reload=False)
