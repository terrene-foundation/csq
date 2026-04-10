"""Health check endpoint -- source only (NEW file, not in target)."""

import time


def health_check(db_connection=None):
    """Return service health status.

    New endpoint added in source that does not exist in target.
    """
    status = {
        "status": "healthy",
        "timestamp": time.time(),
        "checks": {
            "api": "ok",
        },
    }
    if db_connection is not None:
        try:
            db_connection.execute("SELECT 1")
            status["checks"]["database"] = "ok"
        except Exception as e:
            status["status"] = "degraded"
            status["checks"]["database"] = str(e)
    return status
