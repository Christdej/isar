from enum import Enum


class MissionStatus(str, Enum):
    NotStarted: str = "not_started"
    InProgress: str = "in_progress"
    Paused: str = "paused"
    Failed: str = "failed"
    Cancelled: str = "cancelled"
    Successful: str = "successful"
    PartiallySuccessful: str = "partially_successful"


class StepStatus(str, Enum):
    NotStarted: str = "not_started"
    Successful: str = "successful"
    InProgress: str = "in_progress"
    Failed: str = "failed"
    Cancelled: str = "cancelled"


class TaskStatus(str, Enum):
    NotStarted: str = "not_started"
    InProgress: str = "in_progress"
    Paused: str = "paused"
    Failed: str = "failed"
    Cancelled: str = "cancelled"
    Successful: str = "successful"
    PartiallySuccessful: str = "partially_successful"


class RobotStatus(Enum):
    Available: str = "available"
    Busy: str = "busy"
    Offline: str = "offline"
