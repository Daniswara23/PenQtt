import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from PySide6.QtGui import QPixmap
from PySide6.QtCore import Qt
from claude37v24 import PenMQTT

class SplashScreenWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Splash Screen")
        self.setGeometry(100, 100, 1920, 1080)  # Set splash screen size

        # Set up the central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Set white background for the central widget
        central_widget.setStyleSheet("background-color: white;")

        # Layout
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Add a label for "PenQTT"
        penqtt_label = QLabel("PenMQTT", self)
        penqtt_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        penqtt_label.setStyleSheet("font-size: 60px; font-weight: bold; color: #2E86C1;")  # Blue color
        layout.addWidget(penqtt_label)

        # Add a label for "Click To Start"
        click_label = QLabel("Click To Start", self)
        click_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        click_label.setStyleSheet("font-size: 30px; font-weight: bold; color: #34495E;")  # Dark gray color
        layout.addWidget(click_label)

        # Optional: Add a background image
        # self.set_background_image("splash.png")

    def set_background_image(self, image_path):
        # Set a background image (optional)
        pixmap = QPixmap(image_path)
        if not pixmap.isNull():
            background_label = QLabel(self)
            background_label.setPixmap(pixmap.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding))
            background_label.setGeometry(0, 0, self.width(), self.height())
            background_label.lower()  # Move the image to the background

    def keyPressEvent(self, event):
        # Close the splash screen when any key is pressed
        self.close()
        self.open_main_window()

    def mousePressEvent(self, event):
        # Close the splash screen when the mouse is clicked
        self.close()
        self.open_main_window()

    def open_main_window(self):
        # Open the main application window
        self.main_window = PenMQTT()
        self.main_window.showMaximized()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Main Application")
        self.setGeometry(100, 100, 1920, 1080)  # Set main window size

        # Add a label to the main window
        label = QLabel("Welcome to PenQTT!", self)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("font-size: 40px; font-weight: bold; color: black;")
        self.setCentralWidget(label)

def main():
    app = QApplication(sys.argv)

    # Create and show the splash screen window
    splash = SplashScreenWindow()
    splash.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()