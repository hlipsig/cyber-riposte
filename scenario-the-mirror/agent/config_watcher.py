"""
Configuration hot-reload watcher (Phase 9).
Monitors ConfigMap changes and reloads action pool without restart.
"""

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("Watchdog not available. Install with: pip install watchdog")


logger = logging.getLogger(__name__)


class ConfigFileHandler(FileSystemEventHandler):
    """
    File system event handler for configuration files.
    Triggers reload callback when file is modified.
    """

    def __init__(self, file_path: str, reload_callback: Callable):
        """
        Initialize handler.

        Args:
            file_path: Path to file to watch
            reload_callback: Function to call on file change
        """
        super().__init__()
        self.file_path = Path(file_path).resolve()
        self.reload_callback = reload_callback
        self.last_reload = 0
        self.debounce_seconds = 2  # Ignore rapid successive changes

    def on_modified(self, event):
        """Handle file modification event."""
        if event.is_directory:
            return

        # Check if modified file is the one we're watching
        event_path = Path(event.src_path).resolve()
        if event_path != self.file_path:
            return

        # Debounce: ignore if reload happened recently
        now = time.time()
        if now - self.last_reload < self.debounce_seconds:
            logger.debug(f"Ignoring rapid change to {self.file_path.name} (debounced)")
            return

        logger.info(f"Configuration file modified: {self.file_path.name}")

        try:
            self.reload_callback()
            self.last_reload = now
            logger.info(f"Configuration reloaded successfully from {self.file_path.name}")
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")


class ConfigWatcher:
    """
    Watches configuration files for changes and triggers reload.

    Usage:
        watcher = ConfigWatcher()
        watcher.watch("/etc/mirror/config/action-pool.yaml", reload_action_pool)
        watcher.start()
        # ... later ...
        watcher.stop()
    """

    def __init__(self):
        """Initialize configuration watcher."""
        if not WATCHDOG_AVAILABLE:
            logger.warning("Watchdog not available. Hot-reload disabled.")
            self.enabled = False
            return

        self.enabled = True
        self.observer = Observer()
        self.watched_paths = {}
        logger.info("Configuration watcher initialized")

    def watch(self, file_path: str, reload_callback: Callable):
        """
        Watch a configuration file for changes.

        Args:
            file_path: Path to configuration file
            reload_callback: Function to call when file changes
        """
        if not self.enabled:
            logger.warning("Watcher not enabled, skipping watch")
            return

        file_path = Path(file_path).resolve()
        if not file_path.exists():
            logger.error(f"Cannot watch non-existent file: {file_path}")
            return

        # Watch parent directory (Kubernetes ConfigMap updates create new file)
        watch_dir = file_path.parent

        # Create event handler
        handler = ConfigFileHandler(str(file_path), reload_callback)

        # Schedule observer
        self.observer.schedule(handler, str(watch_dir), recursive=False)
        self.watched_paths[str(file_path)] = handler

        logger.info(f"Watching {file_path.name} for changes")

    def start(self):
        """Start watching for configuration changes."""
        if not self.enabled:
            return

        if not self.watched_paths:
            logger.warning("No files being watched")
            return

        self.observer.start()
        logger.info(f"Configuration watcher started (watching {len(self.watched_paths)} files)")

    def stop(self):
        """Stop watching for configuration changes."""
        if not self.enabled:
            return

        self.observer.stop()
        self.observer.join(timeout=5)
        logger.info("Configuration watcher stopped")

    def is_running(self) -> bool:
        """Check if watcher is running."""
        if not self.enabled:
            return False
        return self.observer.is_alive()


# Global watcher instance
_watcher: Optional[ConfigWatcher] = None


def get_config_watcher() -> ConfigWatcher:
    """
    Get singleton configuration watcher instance.

    Returns:
        ConfigWatcher instance
    """
    global _watcher
    if _watcher is None:
        _watcher = ConfigWatcher()
    return _watcher
