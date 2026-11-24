"""
Provenio для iPhone / iPad.

Ядро Provenio (provenio*.py) копируется в этот пакет при сборке (ios/prepare.py).
Приложение поднимает локальный сервер Provenio на 127.0.0.1 и показывает
тот же интерфейс во встроенном WebView (WKWebView).
"""
import os
import sys
import threading
import traceback
from pathlib import Path

import toga
from toga.style.pack import Pack


class Provenio(toga.App):
    def startup(self):
        data = Path(self.paths.data)
        data.mkdir(parents=True, exist_ok=True)
        docs = Path.home() / "Documents"          # видна в «Файлы» (UIFileSharingEnabled)
        docs.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("PROVENIO_DATA", str(data))
        os.environ["PROVENIO_PLATFORM"] = "ios"
        os.environ["PROVENIO_EXPORT_DIR"] = str(docs)
        try:   # на iOS у OpenSSL нет системного хранилища сертификатов — берём certifi
            import certifi
            os.environ["SSL_CERT_FILE"] = certifi.where()
        except ImportError:
            pass
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)

        self.main_window = toga.MainWindow(title=self.formal_name)
        try:
            from http.server import ThreadingHTTPServer
            import provenio_ui as U
            srv = ThreadingHTTPServer(("127.0.0.1", 0), U.Handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            threading.Thread(target=U.monitor_loop, daemon=True).start()
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            self.main_window.content = toga.WebView(url=url, style=Pack(flex=1))
        except Exception:
            err = traceback.format_exc()
            print(err)
            self.main_window.content = toga.MultilineTextInput(
                value="Provenio не запустился:\n\n" + err, readonly=True, style=Pack(flex=1))
        self.main_window.show()


def main():
    return Provenio()
