# ============================================================
# CYBERDUDEBIVASH AI — COST GUARD / TRACKER
# ============================================================

import json
import os
from datetime import datetime, timezone, date
from typing import Dict

COST_FILE = os.path.join("memory", "cost_tracker.json")

# GPT-4o-mini pricing per 1K tokens (USD)
COST_PER_1K_INPUT = 0.00015
COST_PER_1K_OUTPUT = 0.0006
DAILY_LIMIT_USD = float(os.getenv("DAILY_COST_LIMIT_USD", "50.0"))


class CostTracker:
    """Track and enforce AI API cost limits."""

    def record(self, input_tokens: int, output_tokens: int, model: str = "gpt-4o-mini") -> float:
        cost = (input_tokens / 1000 * COST_PER_1K_INPUT) + (output_tokens / 1000 * COST_PER_1K_OUTPUT)
        data = self._load()
        today = str(date.today())

        if today not in data:
            data[today] = {"total_usd": 0.0, "calls": 0}

        data[today]["total_usd"] = round(data[today]["total_usd"] + cost, 6)
        data[today]["calls"] += 1
        self._save(data)
        return cost

    def today_total(self) -> float:
        data = self._load()
        return data.get(str(date.today()), {}).get("total_usd", 0.0)

    def is_within_budget(self) -> bool:
        return self.today_total() < DAILY_LIMIT_USD

    def summary(self) -> Dict:
        data = self._load()
        today = str(date.today())
        return {
            "today_usd": data.get(today, {}).get("total_usd", 0.0),
            "today_calls": data.get(today, {}).get("calls", 0),
            "daily_limit_usd": DAILY_LIMIT_USD,
            "within_budget": self.is_within_budget(),
            "history": {k: v for k, v in list(data.items())[-7:]},  # last 7 days
        }

    def _load(self) -> Dict:
        os.makedirs(os.path.dirname(COST_FILE), exist_ok=True)
        if not os.path.exists(COST_FILE):
            return {}
        try:
            with open(COST_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, data: Dict) -> None:
        os.makedirs(os.path.dirname(COST_FILE), exist_ok=True)
        with open(COST_FILE, "w") as f:
            json.dump(data, f, indent=2)
