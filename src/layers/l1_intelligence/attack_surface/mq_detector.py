"""Message queue and scheduled task entry point detection."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
)

logger = get_logger(__name__)


class MQDetector(ABC):
    """Base class for message queue detectors."""

    framework_name: str = "unknown"
    file_patterns: list[str] = []

    @abstractmethod
    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect MQ consumers in source code."""
        pass


class KafkaDetector(MQDetector):
    """Detector for Kafka consumers."""

    framework_name = "kafka"
    file_patterns = ["*.java", "*.py", "*.go"]

    # Java Spring Kafka: @KafkaListener(topics = "topic-name")
    JAVA_KAFKA_LISTENER = re.compile(
        r"""@KafkaListener\s*\(
        [^)]*?
        topics\s*=\s*["']([^"']+)["']
        [^)]*?
        \)
        [^{]*
        (?:public|private)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*\(""",
        re.VERBOSE | re.DOTALL,
    )

    # Python kafka-python: consumer.subscribe(['topic'])
    PYTHON_SUBSCRIBE = re.compile(
        r"""consumer\.subscribe\s*\(\s*\[?\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    # Python confluent-kafka: .subscribe(['topic'])
    PYTHON_CONFLUENT = re.compile(
        r"""\.subscribe\s*\(\s*\[?\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    # Go sarama: consumer.ConsumePartition("topic", ...)
    GO_SARAMA = re.compile(
        r"""ConsumePartition\s*\(\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Kafka consumers."""
        entry_points = []

        # Java Spring Kafka
        for match in self.JAVA_KAFKA_LISTENER.finditer(content):
            topic = match.group(1)
            handler = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"kafka://{topic}",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "kafka", "topic": topic},
            )
            entry_points.append(entry)

        # Python kafka subscribe
        for match in self.PYTHON_SUBSCRIBE.finditer(content):
            topic = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            handler = self._find_python_handler(content, match.start())

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"kafka://{topic}",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "kafka", "topic": topic},
            )
            entry_points.append(entry)

        # Go sarama
        for match in self.GO_SARAMA.finditer(content):
            topic = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"kafka://{topic}",
                handler="consume",
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "kafka", "topic": topic},
            )
            entry_points.append(entry)

        return entry_points

    def _find_python_handler(self, content: str, start_pos: int) -> str:
        """Find Python handler function."""
        search_content = content[start_pos : start_pos + 500]
        match = re.search(r"def\s+(\w+)\s*\(", search_content)
        if match:
            return match.group(1)
        return "unknown"


class RabbitMQDetector(MQDetector):
    """Detector for RabbitMQ consumers."""

    framework_name = "rabbitmq"
    file_patterns = ["*.java", "*.py", "*.go"]

    # Java Spring AMQP: @RabbitListener(queues = "queue-name")
    JAVA_RABBIT_LISTENER = re.compile(
        r"""@RabbitListener\s*\(
        [^)]*?
        queues\s*=\s*["']([^"']+)["']
        [^)]*?
        \)
        [^{]*
        (?:public|private)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*\(""",
        re.VERBOSE | re.DOTALL,
    )

    # Python pika: channel.basic_consume(queue='queue-name', ...)
    PYTHON_PIKA = re.compile(
        r"""basic_consume\s*\(
        [^)]*?
        queue\s*=\s*["']([^"']+)["']
        """,
        re.VERBOSE,
    )

    # Go amqp: channel.Consume("queue-name", ...)
    GO_AMQP = re.compile(
        r"""\.Consume\s*\(\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect RabbitMQ consumers."""
        entry_points = []

        # Java Spring AMQP
        for match in self.JAVA_RABBIT_LISTENER.finditer(content):
            queue = match.group(1)
            handler = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"amqp://{queue}",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "rabbitmq", "queue": queue},
            )
            entry_points.append(entry)

        # Python pika
        for match in self.PYTHON_PIKA.finditer(content):
            queue = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"amqp://{queue}",
                handler="callback",
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "rabbitmq", "queue": queue},
            )
            entry_points.append(entry)

        # Go amqp
        for match in self.GO_AMQP.finditer(content):
            queue = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"amqp://{queue}",
                handler="consume",
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "rabbitmq", "queue": queue},
            )
            entry_points.append(entry)

        return entry_points


class RedisDetector(MQDetector):
    """Detector for Redis pub/sub consumers."""

    framework_name = "redis"
    file_patterns = ["*.java", "*.py", "*.go"]

    # Java Spring Redis: @RedisListener(patterns = "pattern")
    JAVA_REDIS_LISTENER = re.compile(
        r"""@RedisMessageListener\s*\(
        [^)]*?
        patterns\s*=\s*["']([^"']+)["']
        [^)]*?
        \)
        [^{]*
        (?:public|private)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*\(""",
        re.VERBOSE | re.DOTALL,
    )

    # Python redis: pubsub.subscribe('channel')
    PYTHON_REDIS = re.compile(
        r"""(?:pubsub\.)?subscribe\s*\(\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    # Go redigo: c.Subscribe("channel")
    GO_REDIS = re.compile(
        r"""\.Subscribe\s*\(\s*["']([^"']+)["']""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect Redis pub/sub consumers."""
        entry_points = []

        # Python redis
        for match in self.PYTHON_REDIS.finditer(content):
            channel = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"redis://{channel}",
                handler="on_message",
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "redis", "channel": channel},
            )
            entry_points.append(entry)

        # Go redis
        for match in self.GO_REDIS.finditer(content):
            channel = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.MQ,
                path=f"redis://{channel}",
                handler="on_message",
                file=str(file_path),
                line=line_num,
                framework=self.framework_name,
                metadata={"broker": "redis", "channel": channel},
            )
            entry_points.append(entry)

        return entry_points


class CronDetector:
    """Detector for scheduled tasks (cron jobs)."""

    framework_name = "cron"
    file_patterns = ["*.java", "*.py", "*.go"]

    # Java Spring: @Scheduled(cron = "0 0 12 * * ?")
    JAVA_SCHEDULED = re.compile(
        r"""@Scheduled\s*\(
        [^)]*?
        (?:cron\s*=\s*["']([^"']+)["']|fixedRate\s*=\s*(\d+))
        [^)]*?
        \)
        [^{]*
        (?:public|private)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*\(""",
        re.VERBOSE | re.DOTALL,
    )

    # Python Celery: @app.task or @celery.task (with or without parentheses)
    PYTHON_CELERY = re.compile(
        r"""@(?:app|celery)\.task\s*(?:\([^)]*\))?\s*
        def\s+(\w+)""",
        re.VERBOSE | re.DOTALL,
    )

    # Python Celery beat: @app.on_after_configure.connect
    PYTHON_CELERY_BEAT = re.compile(
        r"""@app\.on_after_configure\.connect""",
        re.VERBOSE,
    )

    # Python schedule: schedule.every(10).seconds.do(job_func)
    PYTHON_SCHEDULE = re.compile(
        r"""schedule\.\w+\([^)]*\)\.do\s*\(\s*(\w+)""",
        re.VERBOSE,
    )

    # Go cron: c.AddFunc("0 * * * *", func)
    GO_CRON = re.compile(
        r"""AddFunc\s*\(\s*["']([^"']+)["']\s*,\s*(\w+)""",
        re.VERBOSE,
    )

    def detect(self, content: str, file_path: Path) -> list[EntryPoint]:
        """Detect scheduled tasks."""
        entry_points = []

        # Java Spring Scheduled
        for match in self.JAVA_SCHEDULED.finditer(content):
            cron_expr = match.group(1) or f"fixedRate:{match.group(2)}"
            handler = match.group(3)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.CRON,
                path=f"cron://{cron_expr}",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework="spring-scheduled",
                metadata={"schedule": cron_expr},
            )
            entry_points.append(entry)

        # Python Celery
        for match in self.PYTHON_CELERY.finditer(content):
            handler = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.CRON,
                path="celery://task",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework="celery",
                metadata={"type": "celery-task"},
            )
            entry_points.append(entry)

        # Python schedule
        for match in self.PYTHON_SCHEDULE.finditer(content):
            handler = match.group(1)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.CRON,
                path="schedule://interval",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework="python-schedule",
            )
            entry_points.append(entry)

        # Go cron
        for match in self.GO_CRON.finditer(content):
            cron_expr = match.group(1)
            handler = match.group(2)
            line_num = content[: match.start()].count("\n") + 1

            entry = EntryPoint(
                type=EntryPointType.CRON,
                path=f"cron://{cron_expr}",
                handler=handler,
                file=str(file_path),
                line=line_num,
                framework="go-cron",
                metadata={"schedule": cron_expr},
            )
            entry_points.append(entry)

        return entry_points


# Registry of all MQ detectors
MQ_DETECTORS: list[type[MQDetector]] = [
    KafkaDetector,
    RabbitMQDetector,
    RedisDetector,
]


def get_mq_detector_for_framework(framework: str) -> MQDetector | None:
    """Get MQ detector for a specific framework."""
    framework_lower = framework.lower()
    for detector_cls in MQ_DETECTORS:
        if detector_cls.framework_name == framework_lower:
            return detector_cls()
    return None


def get_mq_detector_for_file(file_path: Path) -> list[MQDetector]:
    """Get applicable MQ detectors for a file."""
    detectors = []
    suffix = file_path.suffix

    for detector_cls in MQ_DETECTORS:
        for pattern in detector_cls.file_patterns:
            if pattern.startswith("*."):
                if suffix == pattern[1:]:
                    detectors.append(detector_cls())
                    break

    return detectors
