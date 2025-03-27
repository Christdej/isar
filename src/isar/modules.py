import logging
import os
from importlib import import_module
from logging import Logger

from dependency_injector import containers, providers

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
from isar.robot.robot import Robot
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


class ApplicationContainer(containers.DeclarativeContainer):
    config = providers.Configuration(pydantic_settings=[settings])

    # Core services
    keyvault = providers.Singleton(
        Keyvault,
        keyvault_name=settings.KEYVAULT_NAME,
        client_id=settings.AZURE_CLIENT_ID,
        client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
        tenant_id=settings.AZURE_TENANT_ID,
    )

    # Events and shared state
    events = providers.Singleton(Events)
    shared_state = providers.Singleton(SharedState)

    # Robot-related services
    robot_interface = providers.Singleton(
        lambda: import_module(f"{settings.ROBOT_PACKAGE}.robotinterface").Robot()
    )
    robot_utilities = providers.Singleton(RobotUtilities, robot=robot_interface)

    # API and controllers
    authenticator = providers.Singleton(Authenticator)
    scheduling_utilities = providers.Singleton(
        SchedulingUtilities,
        events=events,
        shared_state=shared_state,
        mission_planner=providers.Singleton(LocalPlanner),
    )
    scheduling_controller = providers.Singleton(
        SchedulingController, scheduling_utilities=scheduling_utilities
    )
    robot_controller = providers.Singleton(
        RobotController, robot_utilities=robot_utilities
    )
    api = providers.Singleton(
        API,
        authenticator=authenticator,
        scheduling_controller=scheduling_controller,
        robot_controller=robot_controller,
        keyvault=keyvault,
    )

    # Storage
    local_storage = providers.Singleton(LocalStorage)
    blob_storage = providers.Singleton(BlobStorage, keyvault=keyvault)
    slimm_storage = providers.Singleton(
        SlimmStorage, request_handler=providers.Singleton(RequestHandler)
    )
    storage_handlers = providers.List(local_storage, blob_storage, slimm_storage)

    # Mqtt client
    mqtt_client = (
        providers.Singleton(
            MqttPublisher,
            mqtt_queue=providers.Callable(events.provided.mqtt_queue),
        )
        if settings.MQTT_ENABLED
        else None
    )

    # State machine
    task_selector = providers.Singleton(
        SequentialTaskSelector
        if settings.TASK_SELECTOR == "sequential"
        else TaskSelectorInterface
    )

    state_machine = providers.Singleton(
        StateMachine,
        events=events,
        shared_state=shared_state,
        robot=robot_interface,
        mqtt_publisher=mqtt_client,
        task_selector=task_selector,
    )

    # Robot
    robot = providers.Singleton(
        Robot, events=events, robot=robot_interface, shared_state=shared_state
    )

    # Uploader
    uploader = providers.Singleton(
        Uploader,
        events=events,
        storage_handlers=storage_handlers,
        mqtt_publisher=mqtt_client,
    )


def get_injector() -> ApplicationContainer:
    container = ApplicationContainer()
    container.init_resources()
    container.wire(modules=[__name__])
    container.config.from_dict(
        {
            "KEYVAULT_NAME": settings.KEYVAULT_NAME,
            "MQTT_ENABLED": settings.MQTT_ENABLED,
            "TASK_SELECTOR": settings.TASK_SELECTOR,
        }
    )

    print("Loaded the following module configurations:")
    for provider_name, provider in container.providers.items():
        provider_repr = repr(provider)
        simplified_provider = provider_repr.split(".")[-1].split(">")[0]
        print(f"    {provider_name:<20}: {simplified_provider}")

    return container
