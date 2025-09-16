from django.http import JsonResponse
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from decision_engine.middleware import RedisClientSingleton
import os

APP_VERSION = os.getenv("APP_VERSION", "0.1.0")


def healthz(request):
    """Lightweight: hanya memastikan service hidup."""
    return JsonResponse({
        "status": "ok",
        "app_version": APP_VERSION,
    })


def readyz(request):
    """Deep readiness: cek DB + migrations + Redis."""
    status = {
        "status": "ok",
        "app_version": APP_VERSION,
    }

    # ✅ DB connectivity
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1;")
            cursor.fetchone()
        status["database"] = "ok"
    except Exception as e:
        status["database"] = f"error: {e}"
        status["status"] = "degraded"

    # ✅ Migration check
    try:
        executor = MigrationExecutor(connection)
        plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
        if plan:
            status["migrations"] = f"pending: {len(plan)}"
            status["status"] = "degraded"
        else:
            status["migrations"] = "ok"
    except Exception as e:
        status["migrations"] = f"error: {e}"
        status["status"] = "degraded"

    # ✅ Redis check
    try:
        redis_client = RedisClientSingleton.get_client()
        if redis_client:
            redis_client.ping()
            status["redis"] = "ok"
        else:
            status["redis"] = "not_configured"
    except Exception as e:
        status["redis"] = f"error: {e}"
        status["status"] = "degraded"

    return JsonResponse(status)
