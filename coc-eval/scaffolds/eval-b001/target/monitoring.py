"""Monitoring utilities -- TARGET-ONLY file, not present in source.

This file exists only in the target repository. It must be preserved
during sync (never deleted by an additive sync operation).
"""

import time


class MetricsCollector:
    """Simple in-memory metrics collector."""

    def __init__(self):
        self.counters = {}
        self.gauges = {}

    def increment(self, name, value=1):
        self.counters[name] = self.counters.get(name, 0) + value

    def set_gauge(self, name, value):
        self.gauges[name] = value

    def get_metrics(self):
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "collected_at": time.time(),
        }


def setup_monitoring(app):
    """Attach monitoring to the application.

    Target-specific: integrates with the target's deployment
    infrastructure. Not applicable to the source repository.
    """
    collector = MetricsCollector()
    app.metrics = collector
    return collector
