import pytest

from scheduler.service import SchedulerCore


@pytest.fixture
def core():
    return SchedulerCore()
