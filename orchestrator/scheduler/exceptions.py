class TaskNotFoundError(Exception):
    def __init__(self, task_id: str):
        super().__init__(f"tarefa não encontrada: {task_id}")
        self.task_id = task_id
