"""Tests for Docker deployment and container functionality."""

import pytest
import subprocess
import time
import json
import tempfile
import os
from pathlib import Path


@pytest.fixture
def docker_env_file():
    """Create temporary environment file for Docker testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write("ABUSEIPDB_API_KEY=docker_test_key_12345\n")
        f.write("LOG_LEVEL=DEBUG\n")
        f.write("DAILY_QUOTA=50\n")
        f.write("CACHE_DB_PATH=/app/cache/cache.db\n")
        f.flush()
        yield f.name

    try:
        os.unlink(f.name)
    except FileNotFoundError:
        pass


class TestDockerBuild:
    """Test Docker image building."""

    def test_docker_build_success(self):
        """Test that Docker image builds successfully."""
        # Skip if Docker is not available
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        project_root = Path(__file__).parent.parent
        dockerfile_path = project_root / "docker" / "Dockerfile"

        if not dockerfile_path.exists():
            pytest.skip("Dockerfile not found")

        # Build the Docker image
        build_cmd = [
            "docker", "build",
            "-f", str(dockerfile_path),
            "-t", "mcp-abuseipdb-test",
            str(project_root)
        ]

        try:
            result = subprocess.run(
                build_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            assert result.returncode == 0, f"Docker build failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            pytest.fail("Docker build timed out after 5 minutes")

    def test_docker_image_metadata(self):
        """Test Docker image metadata and labels."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Inspect the image
        inspect_cmd = ["docker", "inspect", "mcp-abuseipdb-test"]

        try:
            result = subprocess.run(
                inspect_cmd,
                capture_output=True,
                text=True,
                check=True
            )

            metadata = json.loads(result.stdout)[0]
            config = metadata["Config"]

            # Check that the image has correct configuration
            assert config["User"] == "mcp", "Should run as non-root user"
            assert config["WorkingDir"] == "/app", "Should set correct working directory"
            assert any("PYTHONPATH=/app/src" in env for env in config["Env"]), "Should set PYTHONPATH"

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")


class TestDockerRun:
    """Test Docker container execution."""

    def test_docker_run_help(self, docker_env_file):
        """Test running container with help/version check."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Test running the container with a simple command
        run_cmd = [
            "docker", "run",
            "--rm",
            "--env-file", docker_env_file,
            "mcp-abuseipdb-test",
            "python", "-c", "import mcp_abuseipdb; print('Import successful')"
        ]

        try:
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            assert result.returncode == 0, f"Container execution failed: {result.stderr}"
            assert "Import successful" in result.stdout

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")
        except subprocess.TimeoutExpired:
            pytest.fail("Container execution timed out")

    def test_docker_run_server_validation(self, docker_env_file):
        """Test running container with server validation."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Test running server with validation only (exit after import)
        run_cmd = [
            "docker", "run",
            "--rm",
            "--env-file", docker_env_file,
            "mcp-abuseipdb-test",
            "python", "-c",
            "from mcp_abuseipdb.server import MCPAbuseIPDBServer; "
            "server = MCPAbuseIPDBServer(); "
            "print(f'Server initialized with {len(server.tools)} tools')"
        ]

        try:
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            assert result.returncode == 0, f"Server validation failed: {result.stderr}"
            assert "Server initialized with 5 tools" in result.stdout

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")
        except subprocess.TimeoutExpired:
            pytest.fail("Server validation timed out")

    def test_docker_run_environment_variables(self, docker_env_file):
        """Test that environment variables are properly passed to container."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Test environment variable passing
        run_cmd = [
            "docker", "run",
            "--rm",
            "--env-file", docker_env_file,
            "mcp-abuseipdb-test",
            "python", "-c",
            "import os; "
            "print(f'API_KEY: {os.getenv(\"ABUSEIPDB_API_KEY\", \"NOT_SET\")}'); "
            "print(f'LOG_LEVEL: {os.getenv(\"LOG_LEVEL\", \"NOT_SET\")}'); "
            "print(f'DAILY_QUOTA: {os.getenv(\"DAILY_QUOTA\", \"NOT_SET\")}')"
        ]

        try:
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            assert result.returncode == 0
            output = result.stdout

            assert "API_KEY: docker_test_key_12345" in output
            assert "LOG_LEVEL: DEBUG" in output
            assert "DAILY_QUOTA: 50" in output

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")

    def test_docker_run_security(self):
        """Test Docker container security configuration."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Test that container runs as non-root user
        run_cmd = [
            "docker", "run",
            "--rm",
            "mcp-abuseipdb-test",
            "id"
        ]

        try:
            result = subprocess.run(
                run_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            assert result.returncode == 0

            # Should run as 'mcp' user, not root
            output = result.stdout
            assert "uid=" in output
            assert "gid=" in output
            assert "(mcp)" in output or "uid=1000" in output or "uid=999" in output
            assert "(root)" not in output or "uid=0" not in output

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")


class TestDockerVolumes:
    """Test Docker volume and persistence functionality."""

    def test_docker_cache_volume(self, docker_env_file):
        """Test that cache volume can be mounted and used."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = os.path.join(temp_dir, "cache")
            os.makedirs(cache_dir, exist_ok=True)

            # Test cache directory mounting
            run_cmd = [
                "docker", "run",
                "--rm",
                "--env-file", docker_env_file,
                "-v", f"{cache_dir}:/app/cache",
                "mcp-abuseipdb-test",
                "python", "-c",
                "import os; "
                "cache_dir = '/app/cache'; "
                "print(f'Cache dir exists: {os.path.exists(cache_dir)}'); "
                "print(f'Cache dir writable: {os.access(cache_dir, os.W_OK)}'); "
                "open('/app/cache/test.txt', 'w').write('test'); "
                "print('Test file created')"
            ]

            try:
                result = subprocess.run(
                    run_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                assert result.returncode == 0
                output = result.stdout

                assert "Cache dir exists: True" in output
                assert "Cache dir writable: True" in output
                assert "Test file created" in output

                # Verify file was created on host
                test_file = os.path.join(cache_dir, "test.txt")
                assert os.path.exists(test_file)
                with open(test_file, 'r') as f:
                    assert f.read() == "test"

            except subprocess.CalledProcessError:
                pytest.skip("Docker image not built or not available")


class TestDockerHealthCheck:
    """Test Docker health check functionality."""

    def test_docker_health_check(self):
        """Test Docker container health check."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Check if image has health check configured
        inspect_cmd = ["docker", "inspect", "mcp-abuseipdb-test"]

        try:
            result = subprocess.run(
                inspect_cmd,
                capture_output=True,
                text=True,
                check=True
            )

            metadata = json.loads(result.stdout)[0]
            config = metadata["Config"]

            # Check health check configuration
            assert "Healthcheck" in config, "Should have health check configured"
            healthcheck = config["Healthcheck"]
            assert "Test" in healthcheck, "Should have health check test"

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")


class TestDockerCompose:
    """Test Docker Compose functionality if docker-compose.yml exists."""

    def test_docker_compose_validation(self):
        """Test docker-compose.yml syntax if it exists."""
        project_root = Path(__file__).parent.parent
        compose_file = project_root / "docker-compose.yml"

        if not compose_file.exists():
            pytest.skip("docker-compose.yml not found")

        try:
            subprocess.run(["docker-compose", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("docker-compose not available")

        # Validate docker-compose.yml syntax
        validate_cmd = [
            "docker-compose",
            "-f", str(compose_file),
            "config"
        ]

        try:
            result = subprocess.run(
                validate_cmd,
                capture_output=True,
                text=True,
                cwd=str(project_root)
            )

            assert result.returncode == 0, f"docker-compose.yml validation failed: {result.stderr}"

        except subprocess.CalledProcessError as e:
            pytest.fail(f"docker-compose validation failed: {e}")


class TestDockerMultiStage:
    """Test multi-stage Docker build optimization."""

    def test_docker_image_size(self):
        """Test that Docker image size is reasonable."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Check image size
        images_cmd = ["docker", "images", "mcp-abuseipdb-test", "--format", "{{.Size}}"]

        try:
            result = subprocess.run(
                images_cmd,
                capture_output=True,
                text=True,
                check=True
            )

            size_str = result.stdout.strip()
            print(f"Docker image size: {size_str}")

            # Basic size check - should be reasonable for a Python app
            # This is mainly for informational purposes
            assert size_str, "Should have image size information"

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")

    def test_docker_layers(self):
        """Test Docker image layer efficiency."""
        try:
            subprocess.run(["docker", "--version"],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Docker not available")

        # Check image history/layers
        history_cmd = ["docker", "history", "mcp-abuseipdb-test", "--no-trunc"]

        try:
            result = subprocess.run(
                history_cmd,
                capture_output=True,
                text=True,
                check=True
            )

            layers = result.stdout.strip().split('\n')
            print(f"Docker image has {len(layers)} layers")

            # Should have reasonable number of layers (not excessive)
            assert len(layers) < 50, f"Too many layers ({len(layers)}), consider optimizing Dockerfile"

        except subprocess.CalledProcessError:
            pytest.skip("Docker image not built or not available")