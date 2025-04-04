import logging
from importlib import import_module
from logging import Logger
from types import ModuleType
from typing import Dict, List, Tuple, Union

from injector import Injector, Module, multiprovider, provider, singleton

from isar.apis.api import API
from isar.apis.robot_control.robot_controller import RobotController
from isar.apis.schedule.scheduling_controller import SchedulingController
from isar.apis.security.authentication import Authenticator
from isar.config.keyvault.keyvault_service import Keyvault
from isar.config.settings import settings
from isar.mission_planner.local_planner import LocalPlanner
from isar.mission_planner.mission_planner_interface import MissionPlannerInterface
from isar.mission_planner.sequential_task_selector import SequentialTaskSelector
from isar.mission_planner.task_selector_interface import TaskSelectorInterface
from isar.models.communication.queues.events import Events, SharedState
from isar.services.service_connections.request_handler import RequestHandler
from isar.services.utilities.robot_utilities import RobotUtilities
from isar.services.utilities.scheduling_utilities import SchedulingUtilities
from isar.state_machine.state_machine import StateMachine
from isar.storage.blob_storage import BlobStorage
from isar.storage.local_storage import LocalStorage
from isar.storage.slimm_storage import SlimmStorage
from isar.storage.storage_interface import StorageInterface
from isar.storage.uploader import Uploader
from robot_interface.robot_interface import RobotInterface
from robot_interface.telemetry.mqtt_client import MqttClientInterface, MqttPublisher


class APIModule(Module):
    @provider
    @singleton
    def provide_api(
        self,
        authenticator: Authenticator,
        scheduling_controller: SchedulingController,
        robot_controller: RobotController,
        keyvault: Keyvault,
    ) -> API:
        return API(authenticator, scheduling_controller, robot_controller, keyvault)

    @provider
    @singleton
    def provide_scheduling_controller(
        self,
        scheduling_utilities: SchedulingUtilities,
    ) -> SchedulingController:
        return SchedulingController(scheduling_utilities)

    @provider
    @singleton
    def provide_robot_controller(
        self,
        robot_utilities: RobotUtilities,
    ) -> RobotController:
        return RobotController(robot_utilities)


class AuthenticationModule(Module):
    @provider
    @singleton
    def provide_authenticator(self) -> Authenticator:
        return Authenticator()


class RobotModule(Module):
    @provider
    @singleton
    def provide_robot_interface(self) -> RobotInterface:
        robot_interface: ModuleType = import_module(
            f"{settings.ROBOT_PACKAGE}.robotinterface"
        )
        return robot_interface.Robot()  # type: ignore


class EventsModule(Module):
    @provider
    @singleton
    def provide_events(self) -> Events:
        return Events()


class SharedStateModule(Module):
    @provider
    @singleton
    def provide_shared_state(self) -> SharedState:
        return SharedState()


class RequestHandlerModule(Module):
    @provider
    @singleton
    def provide_request_handler(self) -> RequestHandler:
        return RequestHandler()


class BlobStorageModule(Module):
    @multiprovider
    @singleton
    def provide_blob_storage(self, keyvault: Keyvault) -> List[StorageInterface]:
        return [BlobStorage(keyvault)]


class LocalStorageModule(Module):
    @multiprovider
    @singleton
    def provide_local_storage(self) -> List[StorageInterface]:
        return [LocalStorage()]


class SlimmStorageModule(Module):
    @multiprovider
    @singleton
    def provide_slimm_storage(
        self, request_handler: RequestHandler
    ) -> List[StorageInterface]:
        return [SlimmStorage(request_handler=request_handler)]


class LocalPlannerModule(Module):
    @provider
    @singleton
    def provide_local_planner(self) -> MissionPlannerInterface:
        return LocalPlanner()


class StateMachineModule(Module):
    @provider
    @singleton
    def provide_state_machine(
        self,
        events: Events,
        shared_state: SharedState,
        robot: RobotInterface,
        mqtt_client: MqttClientInterface,
        task_selector: TaskSelectorInterface,
    ) -> StateMachine:
        return StateMachine(
            events=events,
            shared_state=shared_state,
            robot=robot,
            mqtt_publisher=mqtt_client,
            task_selector=task_selector,
        )


class UploaderModule(Module):
    @provider
    @singleton
    def provide_uploader(
        self,
        events: Events,
        storage_handlers: List[StorageInterface],
        mqtt_client: MqttClientInterface,
    ) -> Uploader:
        return Uploader(
            events=events,
            storage_handlers=storage_handlers,
            mqtt_publisher=mqtt_client,
        )


class SchedulingUtilitiesModule(Module):
    @provider
    @singleton
    def provide_scheduling_utilities(
        self,
        events: Events,
        shared_state: SharedState,
        mission_planner: MissionPlannerInterface,
    ) -> SchedulingUtilities:
        return SchedulingUtilities(events, shared_state, mission_planner)


class RobotUtilitiesModule(Module):
    @provider
    @singleton
    def provide_robot_utilities(self, robot: RobotInterface) -> RobotUtilities:
        return RobotUtilities(robot)


class ServiceModule(Module):
    @provider
    @singleton
    def provide_keyvault(self) -> Keyvault:
        return Keyvault(keyvault_name=settings.KEYVAULT_NAME)


class MqttModule(Module):
    @provider
    @singleton
    def provide_mqtt_client(self, events: Events) -> MqttClientInterface:
        if settings.MQTT_ENABLED:
            return MqttPublisher(mqtt_queue=events.mqtt_queue)
        return None


class SequentialTaskSelectorModule(Module):
    @provider
    @singleton
    def provide_task_selector(self) -> TaskSelectorInterface:
        return SequentialTaskSelector()


modules: Dict[str, Tuple[Module, Union[str, bool]]] = {
    "api": (APIModule, "required"),
    "authentication": (AuthenticationModule, "required"),
    "events": (EventsModule, "required"),
    "shared_state": (SharedStateModule, "required"),
    "request_handler": (RequestHandlerModule, "required"),
    "robot_package": (RobotModule, settings.ROBOT_PACKAGE),
    "isar_id": (RobotModule, settings.ISAR_ID),
    "robot_name": (RobotModule, settings.ROBOT_NAME),
    "mission_planner": (LocalPlannerModule, settings.MISSION_PLANNER),
    "task_selector": (
        {"sequential": SequentialTaskSelectorModule}[settings.TASK_SELECTOR],
        settings.TASK_SELECTOR,
    ),
    "service": (ServiceModule, "required"),
    "state_machine": (StateMachineModule, "required"),
    "storage_local": (LocalStorageModule, settings.STORAGE_LOCAL_ENABLED),
    "storage_blob": (BlobStorageModule, settings.STORAGE_BLOB_ENABLED),
    "storage_slimm": (SlimmStorageModule, settings.STORAGE_SLIMM_ENABLED),
    "mqtt": (MqttModule, "required"),
    "utilities": (SchedulingUtilitiesModule, "required"),
    "robot_utilities": (RobotUtilitiesModule, "required"),
}


def get_injector() -> Injector:
    injector_modules: List[Module] = []
    module_overview: str = ""

    for category, (module, config_option) in modules.items():
        if config_option:
            injector_modules.append(module)
        module_overview += (
            f"\n    {category:<15} : {config_option:<20} ({module.__name__})"
        )

    logger: Logger = logging.getLogger("modules")
    logger.info("Loaded the following module configurations: %s", module_overview)

    return Injector(injector_modules)
