# core/routes/tasks.py
"""Task status/result polling endpoints for async scans."""
from flask import Blueprint, jsonify
from core.task_store import task_store

tasks_bp = Blueprint('tasks', __name__)


@tasks_bp.route('/api/tasks/<task_id>', methods=['GET'])
def get_task_status(task_id: str):
    task = task_store.get(task_id)
    if task is None:
        return jsonify({"success": False, "error": "task not found"}), 404
    return jsonify(task)
