"""
Pytest configuration and fixtures for Docker integration tests.

This module provides:
- Docker availability check
- Test project fixtures for each language
- Shared test utilities
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Generator

import pytest


# =============================================================================
# Docker Markers
# =============================================================================


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "docker: mark test as requiring Docker environment"
    )
    config.addinivalue_line(
        "markers", "codeql: mark test as requiring CodeQL CLI"
    )
    config.addinivalue_line(
        "markers", "network: mark test as requiring network access"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip Docker tests if Docker is not available."""
    docker_available = shutil.which("docker") is not None

    # Check if we're running in a Docker container
    in_docker = os.path.exists("/.dockerenv")

    skip_docker = pytest.mark.skip(
        reason="Docker not available or running inside container"
    )

    for item in items:
        # Skip docker tests if Docker is not available or we're already in Docker
        if "docker" in item.keywords and (not docker_available or in_docker):
            item.add_marker(skip_docker)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def docker_available() -> bool:
    """Check if Docker is available."""
    return shutil.which("docker") is not None


@pytest.fixture
def in_docker() -> bool:
    """Check if running inside a Docker container."""
    return os.path.exists("/.dockerenv")


@pytest.fixture
def codeql_available() -> bool:
    """Check if CodeQL CLI is available."""
    return shutil.which("codeql") is not None


@pytest.fixture
def test_runtime_root(tmp_path: Path) -> Path:
    """Create a runtime root directory for testing."""
    runtime_root = tmp_path / "runtimes"
    runtime_root.mkdir(parents=True, exist_ok=True)
    return runtime_root


# =============================================================================
# Test Project Fixtures
# =============================================================================


@pytest.fixture
def python_project(tmp_path: Path) -> Path:
    """Create a simple Python project for testing."""
    project_dir = tmp_path / "python_test_project"
    project_dir.mkdir()

    # Create a simple vulnerable Python app
    src_dir = project_dir / "src"
    src_dir.mkdir()

    # Vulnerable code: SQL injection
    (src_dir / "app.py").write_text('''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return str(cursor.fetchone())

@app.route("/eval")
def eval_code():
    code = request.args.get("code")
    # Code injection vulnerability
    result = eval(code)
    return str(result)

if __name__ == "__main__":
    app.run(debug=True)
''')

    # Create requirements.txt
    (project_dir / "requirements.txt").write_text("flask>=2.0.0\n")

    # Create pyproject.toml
    (project_dir / "pyproject.toml").write_text('''
[project]
name = "vulnerable-python-app"
version = "0.1.0"
dependencies = ["flask>=2.0.0"]
''')

    return project_dir


@pytest.fixture
def javascript_project(tmp_path: Path) -> Path:
    """Create a simple JavaScript/Node.js project for testing."""
    project_dir = tmp_path / "javascript_test_project"
    project_dir.mkdir()

    # Create a simple vulnerable Node.js app
    src_dir = project_dir / "src"
    src_dir.mkdir()

    # Vulnerable code: Command injection, path traversal
    (src_dir / "app.js").write_text('''
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    // Command injection vulnerability
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

app.get('/file', (req, res) => {
    const filename = req.query.name;
    // Path traversal vulnerability
    const filepath = path.join(__dirname, 'files', filename);
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));
''')

    # Create package.json
    (project_dir / "package.json").write_text('''{
    "name": "vulnerable-node-app",
    "version": "1.0.0",
    "main": "src/app.js",
    "dependencies": {
        "express": "^4.18.0"
    }
}''')

    return project_dir


@pytest.fixture
def typescript_project(tmp_path: Path) -> Path:
    """Create a TypeScript project for testing."""
    project_dir = tmp_path / "typescript_test_project"
    project_dir.mkdir()

    src_dir = project_dir / "src"
    src_dir.mkdir()

    # Vulnerable TypeScript code
    (src_dir / "app.ts").write_text('''
import express from 'express';
import { exec } from 'child_process';

const app = express();

app.get('/eval', (req, res) => {
    const code = req.query.code as string;
    // Unsafe eval
    const result = eval(code);
    res.json({ result });
});

app.listen(3000);
''')

    # Create package.json
    (project_dir / "package.json").write_text('''{
    "name": "vulnerable-ts-app",
    "version": "1.0.0",
    "main": "dist/app.js",
    "scripts": {
        "build": "tsc"
    },
    "dependencies": {
        "express": "^4.18.0"
    },
    "devDependencies": {
        "typescript": "^5.0.0",
        "@types/express": "^4.17.0"
    }
}''')

    # Create tsconfig.json
    (project_dir / "tsconfig.json").write_text('''{
    "compilerOptions": {
        "target": "ES2020",
        "module": "commonjs",
        "outDir": "./dist",
        "strict": true
    },
    "include": ["src/**/*"]
}''')

    return project_dir


@pytest.fixture
def go_project(tmp_path: Path) -> Path:
    """Create a Go project for testing."""
    project_dir = tmp_path / "go_test_project"
    project_dir.mkdir()

    # Create go.mod
    (project_dir / "go.mod").write_text('''module vulnerable-go-app

go 1.22

require github.com/gin-gonic/gin v1.9.0
''')

    # Create vulnerable Go code
    (project_dir / "main.go").write_text('''
package main

import (
    "os/exec"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    // Command injection vulnerability
    r.GET("/ping", func(c *gin.Context) {
        host := c.Query("host")
        cmd := exec.Command("ping", "-c", "4", host)
        output, _ := cmd.CombinedOutput()
        c.String(200, string(output))
    })

    r.Run(":8080")
}
''')

    return project_dir


@pytest.fixture
def java_maven_project(tmp_path: Path) -> Path:
    """Create a Java Maven project for testing."""
    project_dir = tmp_path / "java_test_project"
    src_dir = project_dir / "src" / "main" / "java" / "com" / "example"
    src_dir.mkdir(parents=True)

    # Vulnerable Java code: SQL injection
    (src_dir / "UserController.java").write_text('''
package com.example;

import java.sql.*;
import javax.servlet.http.*;

public class UserController {
    public User getUser(HttpServletRequest request) throws SQLException {
        String userId = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            User user = new User();
            user.setId(rs.getInt("id"));
            user.setName(rs.getString("name"));
            return user;
        }
        return null;
    }
}

class User {
    private int id;
    private String name;

    public void setId(int id) { this.id = id; }
    public void setName(String name) { this.name = name; }
    public int getId() { return id; }
    public String getName() { return name; }
}
''')

    # Create pom.xml
    (project_dir / "pom.xml").write_text('''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>vulnerable-java-app</artifactId>
    <version>1.0.0</version>

    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>4.0.1</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.33</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
        </plugins>
    </build>
</project>
''')

    return project_dir


@pytest.fixture
def cpp_project(tmp_path: Path) -> Path:
    """Create a C/C++ project for testing."""
    project_dir = tmp_path / "cpp_test_project"
    project_dir.mkdir()

    # Vulnerable C code: Buffer overflow, format string
    (project_dir / "main.c").write_text('''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_input(const char *input) {
    char buffer[64];
    // Buffer overflow vulnerability
    strcpy(buffer, input);
    printf("Processed: %s\\n", buffer);
}

void log_message(const char *fmt, ...) {
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    // Format string vulnerability
    vsprintf(buffer, fmt, args);
    va_end(args);
    printf("%s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
''')

    # Create CMakeLists.txt
    (project_dir / "CMakeLists.txt").write_text('''
cmake_minimum_required(VERSION 3.10)
project(vulnerable_c_app C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(main main.c)

# Export compile commands for CodeQL
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
''')

    return project_dir


# =============================================================================
# Utility Fixtures
# =============================================================================


@pytest.fixture
def mock_runtime_root(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a mock runtime root with pre-installed versions."""
    runtime_root = tmp_path / "opt" / "runtimes"
    runtime_root.mkdir(parents=True)

    # The actual installation would happen via RuntimeVersionManager
    # Here we just ensure the directory structure exists

    yield runtime_root

    # Cleanup is handled by tmp_path fixture
