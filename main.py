import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.app import TrafficAnalysisApp
from src.gui.main_window import TrafficAnalyzerGUI


def main() -> None:
    app = TrafficAnalysisApp(config_path=str(ROOT / "config" / "config.json"))
    gui = TrafficAnalyzerGUI(app)
    gui.run()


if __name__ == "__main__":
    main()
