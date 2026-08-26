"""Gateway entry point: starts both the gateway API and admin panel.

Usage:
    python -m raucle.gateway_server

Environment variables (see GatewayConfig for full list):
    RAUCLE_ADMIN_KEY       Admin panel API key (required)
    RAUCLE_SIGNER          Signer backend: local, aws, azure, vault
    RAUCLE_POLICY_FILE     Path to policy YAML file
    RAUCLE_Siem_ENABLED    Enable SIEM forwarding (true/false)
"""

from __future__ import annotations

import logging
import multiprocessing
import sys

import uvicorn

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def run_gateway_app(config: GatewayConfig, gateway: RaucleGateway) -> None:
    """Run the gateway API (agent-facing) on the main port."""
    app = create_gateway_app(gateway)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


def run_admin_app(
    config: GatewayConfig,
    gateway: RaucleGateway,
    users: UserManager,
) -> None:
    """Run the admin panel on the admin port."""
    app = create_admin_app(gateway, users)
    uvicorn.run(app, host=config.host, port=config.admin_port, log_level="info")


def main() -> None:
    config = GatewayConfig.from_env()

    if not config.admin_api_key:
        logger.warning(
            "RAUCLE_ADMIN_KEY is not set. Admin panel will be open with no auth. "
            "Set RAUCLE_ADMIN_KEY to secure it."
        )

    # Initialise gateway
    logger.info("Initialising Raucle Gateway...")
    gateway = RaucleGateway(config)

    # Initialise user management
    users = UserManager()
    # Create a default admin user from RAUCLE_ADMIN_KEY
    if config.admin_api_key:
        users.add_user(config.admin_api_key, "admin", "Default Admin")
        logger.info("Default admin user created from RAUCLE_ADMIN_KEY")

    # Start both servers in separate processes
    logger.info("Starting gateway API on %s:%d", config.host, config.port)
    logger.info("Starting admin panel on %s:%d", config.host, config.admin_port)

    gateway_proc = multiprocessing.Process(
        target=run_gateway_app,
        args=(config, gateway),
        name="raucle-gateway",
    )
    admin_proc = multiprocessing.Process(
        target=run_admin_app,
        args=(config, gateway, users),
        name="raucle-admin",
    )

    gateway_proc.start()
    admin_proc.start()

    logger.info("Gateway started. Press Ctrl-C to stop.")

    try:
        gateway_proc.join()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        gateway_proc.terminate()
        admin_proc.terminate()
        gateway_proc.join()
        admin_proc.join()
        sys.exit(0)


if __name__ == "__main__":
    main()
