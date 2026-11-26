from PySide6.QtCore import QObject, QTimer
from PySide6.QtNetwork import QNetworkInformation


class AutoConnect(QObject):
    """Start the selected engine once on startup or when Internet returns."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self._handled = False
        self._manual_stop = False
        self._information = None
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self.check)

    def configure(self):
        if not self.window.global_settings.snapshot().auto_connect:
            self._timer.stop()
            self._handled = False
            self._manual_stop = False
            return
        if self._information is None and QNetworkInformation.loadBackendByFeatures(
            QNetworkInformation.Feature.Reachability
        ):
            self._information = QNetworkInformation.instance()
            self._information.reachabilityChanged.connect(self.check)
        self._timer.start()
        QTimer.singleShot(0, self.check)

    def user_stopped(self):
        self._handled = True
        self._manual_stop = True

    def check(self):
        window = self.window
        preferences = window.global_settings.snapshot()
        if window._closing or not preferences.auto_connect:
            return
        reachability = (self._information.reachability() if self._information is not None
                        else QNetworkInformation.Reachability.Unknown)
        self.observe(reachability)

    def observe(self, reachability):
        window = self.window
        states = QNetworkInformation.Reachability
        if reachability == states.Disconnected:
            self._manual_stop = False
        if reachability in (states.Disconnected, states.Local, states.Site) and not self._manual_stop:
            self._handled = False
        if reachability != states.Online or self._handled:
            return
        if window._engine_switching or getattr(window, "_engine_guard_pending", False):
            return
        if window._engine_busy():
            self._handled = True
        elif not getattr(window, "_maker_running", False):
            self._handled = True
            window.toggle_connection(automatic=True)
