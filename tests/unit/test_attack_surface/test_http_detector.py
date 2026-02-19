"""Unit tests for attack surface detection."""

from pathlib import Path

from src.layers.l1_intelligence.attack_surface.detector import AttackSurfaceDetector
from src.layers.l1_intelligence.attack_surface.http_detector import (
    EchoDetector,
    FastAPIDetector,
    FlaskDetector,
    GinDetector,
    SpringDetector,
)
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)
from src.layers.l1_intelligence.attack_surface.mq_detector import (
    CronDetector,
    KafkaDetector,
    RabbitMQDetector,
)
from src.layers.l1_intelligence.attack_surface.rpc_detector import (
    DubboDetector,
    GrpcDetector,
    ThriftDetector,
)


class TestGinDetector:
    """Tests for Gin framework detector."""

    def test_detect_simple_route(self, tmp_path: Path) -> None:
        """Test detecting simple Gin route."""
        detector = GinDetector()
        code = '''
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/users", getUsers)
    r.POST("/users", createUser)
    r.Run()
}
'''
        go_file = tmp_path / "main.go"
        go_file.write_text(code)

        entry_points = detector.detect(code, go_file)

        assert len(entry_points) == 2
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[0].path == "/users"
        assert entry_points[0].handler == "getUsers"
        assert entry_points[1].method == HTTPMethod.POST
        assert entry_points[1].path == "/users"

    def test_detect_route_with_params(self, tmp_path: Path) -> None:
        """Test detecting Gin route with path parameters."""
        detector = GinDetector()
        code = '''
r.GET("/users/:id", getUserByID)
r.DELETE("/users/:id/posts/:postId", deletePost)
'''
        go_file = tmp_path / "routes.go"
        go_file.write_text(code)

        entry_points = detector.detect(code, go_file)

        assert len(entry_points) == 2
        assert entry_points[0].path == "/users/{id}"
        assert entry_points[1].path == "/users/{id}/posts/{postId}"

    def test_framework_name(self) -> None:
        """Test framework name is set correctly."""
        detector = GinDetector()
        assert detector.framework_name == "gin"


class TestEchoDetector:
    """Tests for Echo framework detector."""

    def test_detect_echo_route(self, tmp_path: Path) -> None:
        """Test detecting Echo route."""
        detector = EchoDetector()
        code = '''
package main

import "github.com/labstack/echo/v4"

func main() {
    e := echo.New()
    e.GET("/api/hello", helloHandler)
    e.POST("/api/data", dataHandler)
}
'''
        go_file = tmp_path / "main.go"
        go_file.write_text(code)

        entry_points = detector.detect(code, go_file)

        assert len(entry_points) == 2
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[0].path == "/api/hello"
        assert entry_points[1].method == HTTPMethod.POST


class TestSpringDetector:
    """Tests for Spring Boot framework detector."""

    def test_detect_spring_route(self, tmp_path: Path) -> None:
        """Test detecting Spring Boot route."""
        detector = SpringDetector()
        code = '''
package com.example.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers() { }

    @PostMapping("/users")
    public User createUser(@RequestBody User user) { }

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) { }
}
'''
        java_file = tmp_path / "UserController.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) >= 2
        # Check that class prefix is combined with method path
        paths = [e.path for e in entry_points]
        assert any("/api/users" in p for p in paths)

    def test_detect_delete_mapping(self, tmp_path: Path) -> None:
        """Test detecting DELETE mapping."""
        detector = SpringDetector()
        code = '''
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { }
'''
        java_file = tmp_path / "User.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) == 1
        assert entry_points[0].method == HTTPMethod.DELETE


class TestFlaskDetector:
    """Tests for Flask framework detector."""

    def test_detect_flask_route(self, tmp_path: Path) -> None:
        """Test detecting Flask route."""
        detector = FlaskDetector()
        code = '''
from flask import Flask

app = Flask(__name__)

@app.route('/users', methods=['GET'])
def get_users():
    pass

@app.route('/users', methods=['POST'])
def create_user():
    pass
'''
        py_file = tmp_path / "app.py"
        py_file.write_text(code)

        entry_points = detector.detect(code, py_file)

        assert len(entry_points) == 2
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[1].method == HTTPMethod.POST

    def test_detect_method_shortcuts(self, tmp_path: Path) -> None:
        """Test detecting Flask method shortcuts."""
        detector = FlaskDetector()
        code = '''
@app.get('/status')
def status():
    pass

@app.post('/login')
def login():
    pass

@app.delete('/users/<int:id>')
def delete_user(id):
    pass
'''
        py_file = tmp_path / "app.py"
        py_file.write_text(code)

        entry_points = detector.detect(code, py_file)

        assert len(entry_points) == 3
        # Check path normalization
        delete_entry = next(e for e in entry_points if e.method == HTTPMethod.DELETE)
        assert delete_entry.path == "/users/{id}"

    def test_normalize_flask_path(self) -> None:
        """Test Flask path normalization."""
        detector = FlaskDetector()

        assert detector._normalize_path("/users/<int:id>") == "/users/{id}"
        assert detector._normalize_path("/posts/<string:slug>") == "/posts/{slug}"
        assert detector._normalize_path("/items/<id>") == "/items/{id}"


class TestFastAPIDetector:
    """Tests for FastAPI framework detector."""

    def test_detect_fastapi_route(self, tmp_path: Path) -> None:
        """Test detecting FastAPI route."""
        detector = FastAPIDetector()
        code = '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    pass

@app.post("/users")
async def create_user(user: User):
    pass

@app.get("/items/{item_id}")
async def read_item(item_id: int):
    pass
'''
        py_file = tmp_path / "main.py"
        py_file.write_text(code)

        entry_points = detector.detect(code, py_file)

        assert len(entry_points) == 3
        assert entry_points[0].method == HTTPMethod.GET
        assert entry_points[0].path == "/users"


class TestAttackSurfaceDetector:
    """Tests for main AttackSurfaceDetector."""

    def test_detect_empty_directory(self, tmp_path: Path) -> None:
        """Test detecting in empty directory."""
        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path)

        assert report.total_entry_points == 0
        assert report.files_scanned == 0

    def test_detect_gin_project(self, tmp_path: Path) -> None:
        """Test detecting Gin project."""
        # Create Go file with Gin routes
        go_dir = tmp_path / "src"
        go_dir.mkdir()
        go_file = go_dir / "main.go"
        go_file.write_text('''
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/ping", pingHandler)
    r.POST("/data", dataHandler)
    r.Run()
}
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path, frameworks=["gin"])

        assert report.http_endpoints == 2
        assert "gin" in report.frameworks_detected

    def test_detect_flask_project(self, tmp_path: Path) -> None:
        """Test detecting Flask project."""
        py_file = tmp_path / "app.py"
        py_file.write_text('''
from flask import Flask

app = Flask(__name__)

@app.route('/api/hello', methods=['GET'])
def hello():
    return "Hello"
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path, frameworks=["flask"])

        assert report.http_endpoints == 1
        assert "flask" in report.frameworks_detected

    def test_detect_spring_project(self, tmp_path: Path) -> None:
        """Test detecting Spring Boot project."""
        java_dir = tmp_path / "src" / "main" / "java" / "com" / "example"
        java_dir.mkdir(parents=True)
        java_file = java_dir / "Controller.java"
        java_file.write_text('''
package com.example;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class Controller {
    @GetMapping("/users")
    public String getUsers() { return "users"; }
}
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path, frameworks=["spring"])

        assert report.http_endpoints >= 1

    def test_skip_test_directories(self, tmp_path: Path) -> None:
        """Test that test directories are skipped."""
        # Create test file
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        test_file = test_dir / "app.py"
        test_file.write_text('''
from flask import Flask
app = Flask(__name__)
@app.route('/test', methods=['GET'])
def test_route():
    pass
''')

        # Create main file
        main_file = tmp_path / "main.py"
        main_file.write_text('''
from flask import Flask
app = Flask(__name__)
@app.route('/main', methods=['GET'])
def main_route():
    pass
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path)

        # Should only find the main route, not the test route
        assert report.http_endpoints == 1
        assert report.entry_points[0].path == "/main"

    def test_report_summary(self, tmp_path: Path) -> None:
        """Test report summary generation."""
        py_file = tmp_path / "app.py"
        py_file.write_text('''
from flask import Flask
app = Flask(__name__)
@app.route('/users', methods=['GET'])
def get_users():
    pass
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path)

        summary = report.get_summary()
        assert summary["http_endpoints"] == 1
        assert summary["total_entry_points"] == 1
        assert "flask" in summary["frameworks"]


class TestEntryPointModel:
    """Tests for EntryPoint model."""

    def test_to_display_http(self) -> None:
        """Test display string for HTTP entry."""
        entry = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/api/users",
            handler="get_users",
            file="app.py",
            line=10,
        )
        assert entry.to_display() == "GET /api/users -> get_users"

    def test_to_display_post(self) -> None:
        """Test display string for POST entry."""
        entry = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.POST,
            path="/api/login",
            handler="login",
            file="auth.py",
            line=20,
        )
        assert entry.to_display() == "POST /api/login -> login"


class TestAttackSurfaceReport:
    """Tests for AttackSurfaceReport model."""

    def test_add_entry_point_updates_stats(self) -> None:
        """Test that adding entry points updates statistics."""
        report = AttackSurfaceReport(source_path="/test")

        entry1 = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/users",
            handler="get_users",
            file="app.py",
            line=1,
        )
        report.add_entry_point(entry1)

        assert report.http_endpoints == 1
        assert report.total_entry_points == 1

        entry2 = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.POST,
            path="/users",
            handler="create_user",
            file="app.py",
            line=5,
        )
        report.add_entry_point(entry2)

        assert report.http_endpoints == 2
        assert report.total_entry_points == 2

    def test_get_unauthenticated(self) -> None:
        """Test filtering unauthenticated endpoints."""
        report = AttackSurfaceReport(source_path="/test")

        entry1 = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/public",
            handler="public_api",
            file="app.py",
            line=1,
            auth_required=False,
        )
        entry2 = EntryPoint(
            type=EntryPointType.HTTP,
            method=HTTPMethod.GET,
            path="/private",
            handler="private_api",
            file="app.py",
            line=5,
            auth_required=True,
        )

        report.add_entry_point(entry1)
        report.add_entry_point(entry2)

        unauth = report.get_unauthenticated()
        assert len(unauth) == 1
        assert unauth[0].path == "/public"


class TestDubboDetector:
    """Tests for Dubbo RPC detector."""

    def test_detect_dubbo_service(self, tmp_path: Path) -> None:
        """Test detecting Dubbo service."""
        detector = DubboDetector()
        code = '''
package com.example.service;

import org.apache.dubbo.config.annotation.DubboService;

@DubboService(version = "1.0.0")
public class UserServiceImpl implements UserService {
    public User getUser(Long id) {
        return null;
    }
}
'''
        java_file = tmp_path / "UserServiceImpl.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) == 1
        assert entry_points[0].type == EntryPointType.RPC
        assert entry_points[0].framework == "dubbo"
        assert "UserServiceImpl" in entry_points[0].handler

    def test_detect_dubbo_service_with_group(self, tmp_path: Path) -> None:
        """Test detecting Dubbo service with group."""
        detector = DubboDetector()
        code = '''
@DubboService(group = "user", version = "2.0.0")
public class OrderServiceImpl implements OrderService {
}
'''
        java_file = tmp_path / "OrderServiceImpl.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) == 1
        assert "user" in entry_points[0].path


class TestGrpcDetector:
    """Tests for gRPC detector."""

    def test_detect_grpc_service(self, tmp_path: Path) -> None:
        """Test detecting gRPC service."""
        detector = GrpcDetector()
        code = '''
syntax = "proto3";

package helloworld;

service Greeter {
  rpc SayHello(HelloRequest) returns (HelloReply) {}
  rpc SayHelloStream(HelloRequest) returns (stream HelloReply) {}
}

message HelloRequest {
  string name = 1;
}

message HelloReply {
  string message = 1;
}
'''
        proto_file = tmp_path / "helloworld.proto"
        proto_file.write_text(code)

        entry_points = detector.detect(code, proto_file)

        assert len(entry_points) == 2
        assert entry_points[0].type == EntryPointType.GRPC
        assert entry_points[0].framework == "grpc"
        assert "Greeter" in entry_points[0].path


class TestThriftDetector:
    """Tests for Thrift detector."""

    def test_detect_thrift_service(self, tmp_path: Path) -> None:
        """Test detecting Thrift service."""
        detector = ThriftDetector()
        code = '''
namespace java com.example

service UserService {
    User getUser(1: i64 id),
    void createUser(1: User user),
}
'''
        thrift_file = tmp_path / "user.thrift"
        thrift_file.write_text(code)

        entry_points = detector.detect(code, thrift_file)

        assert len(entry_points) == 2
        assert entry_points[0].type == EntryPointType.RPC
        assert entry_points[0].framework == "thrift"
        assert "UserService" in entry_points[0].path


class TestAttackSurfaceDetectorRPC:
    """Tests for AttackSurfaceDetector with RPC detection."""

    def test_detect_dubbo_project(self, tmp_path: Path) -> None:
        """Test detecting Dubbo project."""
        java_dir = tmp_path / "src" / "main" / "java" / "com" / "example"
        java_dir.mkdir(parents=True)
        java_file = java_dir / "ServiceImpl.java"
        java_file.write_text('''
package com.example;

import org.apache.dubbo.config.annotation.DubboService;

@DubboService(version = "1.0.0")
public class HelloServiceImpl implements HelloService {
    public String sayHello(String name) {
        return "Hello " + name;
    }
}
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path, frameworks=["dubbo"])

        assert report.rpc_services >= 1
        assert "dubbo" in report.frameworks_detected

    def test_detect_grpc_project(self, tmp_path: Path) -> None:
        """Test detecting gRPC project."""
        proto_dir = tmp_path / "proto"
        proto_dir.mkdir()
        proto_file = proto_dir / "service.proto"
        proto_file.write_text('''
syntax = "proto3";
service MyService {
  rpc DoSomething(Request) returns (Response) {}
}
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path, frameworks=["grpc"])

        assert report.grpc_services >= 1
        assert "grpc" in report.frameworks_detected


class TestKafkaDetector:
    """Tests for Kafka detector."""

    def test_detect_java_kafka_listener(self, tmp_path: Path) -> None:
        """Test detecting Java Spring Kafka listener."""
        detector = KafkaDetector()
        code = '''
@KafkaListener(topics = "user-events")
public void consumeUserEvent(UserEvent event) {
    processEvent(event);
}
'''
        java_file = tmp_path / "Consumer.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) == 1
        assert entry_points[0].type == EntryPointType.MQ
        assert entry_points[0].framework == "kafka"
        assert "user-events" in entry_points[0].path

    def test_detect_python_kafka_subscribe(self, tmp_path: Path) -> None:
        """Test detecting Python Kafka subscribe."""
        detector = KafkaDetector()
        code = '''
consumer.subscribe(['orders'])
for msg in consumer:
    process_order(msg)
'''
        py_file = tmp_path / "consumer.py"
        py_file.write_text(code)

        entry_points = detector.detect(code, py_file)

        assert len(entry_points) == 1
        assert "orders" in entry_points[0].path


class TestRabbitMQDetector:
    """Tests for RabbitMQ detector."""

    def test_detect_java_rabbit_listener(self, tmp_path: Path) -> None:
        """Test detecting Java Spring RabbitMQ listener."""
        detector = RabbitMQDetector()
        code = '''
@RabbitListener(queues = "task-queue")
public void handleTask(Task task) {
    executeTask(task);
}
'''
        java_file = tmp_path / "TaskConsumer.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) == 1
        assert entry_points[0].type == EntryPointType.MQ
        assert entry_points[0].framework == "rabbitmq"


class TestCronDetector:
    """Tests for Cron/Scheduled task detector."""

    def test_detect_java_scheduled(self, tmp_path: Path) -> None:
        """Test detecting Java Spring @Scheduled."""
        detector = CronDetector()
        code = '''
@Scheduled(cron = "0 0 12 * * ?")
public void dailyCleanup() {
    cleanupOldData();
}
'''
        java_file = tmp_path / "ScheduledTasks.java"
        java_file.write_text(code)

        entry_points = detector.detect(code, java_file)

        assert len(entry_points) == 1
        assert entry_points[0].type == EntryPointType.CRON
        assert "dailyCleanup" in entry_points[0].handler

    def test_detect_celery_task(self, tmp_path: Path) -> None:
        """Test detecting Python Celery task."""
        detector = CronDetector()
        code = '''
@app.task
def send_email(to, subject, body):
    mailer.send(to, subject, body)
'''
        py_file = tmp_path / "tasks.py"
        py_file.write_text(code)

        entry_points = detector.detect(code, py_file)

        assert len(entry_points) == 1
        assert entry_points[0].framework == "celery"
        assert "send_email" in entry_points[0].handler

    def test_detect_go_cron(self, tmp_path: Path) -> None:
        """Test detecting Go cron job."""
        detector = CronDetector()
        code = '''
c := cron.New()
c.AddFunc("0 * * * *", hourlyCleanup)
c.Start()
'''
        go_file = tmp_path / "scheduler.go"
        go_file.write_text(code)

        entry_points = detector.detect(code, go_file)

        assert len(entry_points) == 1
        assert entry_points[0].type == EntryPointType.CRON
        assert "hourlyCleanup" in entry_points[0].handler


class TestAttackSurfaceDetectorFull:
    """Full integration tests for AttackSurfaceDetector."""

    def test_detect_full_project(self, tmp_path: Path) -> None:
        """Test detecting all entry point types."""
        # Create HTTP endpoint
        http_dir = tmp_path / "api"
        http_dir.mkdir()
        http_file = http_dir / "routes.py"
        http_file.write_text('''
from flask import Flask
app = Flask(__name__)
@app.route("/api/users", methods=["GET"])
def get_users():
    pass
''')

        # Create gRPC service
        proto_dir = tmp_path / "proto"
        proto_dir.mkdir()
        proto_file = proto_dir / "service.proto"
        proto_file.write_text('''
service UserService {
  rpc GetUser(GetUserRequest) returns (User) {}
}
''')

        # Create scheduled task
        task_file = tmp_path / "tasks.py"
        task_file.write_text('''
@app.task
def cleanup_expired_sessions():
    pass
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path)

        # Should detect at least HTTP and gRPC
        assert report.total_entry_points >= 2
        assert report.http_endpoints >= 1
        assert report.grpc_services >= 1

    def test_generate_markdown_report(self, tmp_path: Path) -> None:
        """Test markdown report generation."""
        py_file = tmp_path / "app.py"
        py_file.write_text('''
from flask import Flask
app = Flask(__name__)
@app.route("/health", methods=["GET"])
def health():
    return "OK"
''')

        detector = AttackSurfaceDetector()
        report = detector.detect(tmp_path)
        markdown = detector.generate_report_markdown(report)

        assert "# Attack Surface Report" in markdown
        assert "HTTP Endpoints" in markdown
        assert "/health" in markdown
