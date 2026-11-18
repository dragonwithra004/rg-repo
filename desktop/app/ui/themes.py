"""Dark and Light QSS themes for RG Studio Management System."""

DARK_QSS = """
QMainWindow, QDialog, QWidget {
    background-color: #0F172A;
    color: #E2E8F0;
    font-family: "Segoe UI", "Plus Jakarta Sans", sans-serif;
    font-size: 13px;
}
QFrame#Sidebar {
    background-color: #0B1120;
    border-right: 1px solid #1E293B;
}
QFrame#TopBar {
    background-color: #0F172A;
    border-bottom: 1px solid #1E293B;
}
QFrame#SurfaceCard {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 8px;
}
QPushButton#NavButton {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-radius: 6px;
    padding: 9px 12px;
    text-align: left;
    font-weight: 500;
}
QPushButton#NavButton:hover {
    background-color: #1E293B;
    color: #F8FAFC;
}
QPushButton#NavButton[active="true"] {
    background-color: #1D4ED8;
    color: #FFFFFF;
    font-weight: 600;
}
QPushButton#PrimaryButton {
    background-color: #2563EB;
    color: #FFFFFF;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton#PrimaryButton:hover {
    background-color: #1D4ED8;
}
QPushButton#SecondaryButton {
    background-color: #1E293B;
    color: #E2E8F0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton#SecondaryButton:hover {
    background-color: #334155;
}
QLineEdit, QComboBox {
    background-color: #0B1120;
    color: #F8FAFC;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 10px;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #3B82F6;
}
QTableWidget {
    background-color: #1E293B;
    alternate-background-color: #172033;
    gridline-color: #334155;
    border: 1px solid #334155;
    border-radius: 6px;
}
QHeaderView::section {
    background-color: #0B1120;
    color: #94A3B8;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #334155;
    font-weight: 600;
}
"""

LIGHT_QSS = """
QMainWindow, QDialog, QWidget {
    background-color: #F8FAFC;
    color: #0F172A;
    font-family: "Segoe UI", "Plus Jakarta Sans", sans-serif;
    font-size: 13px;
}
QFrame#Sidebar {
    background-color: #FFFFFF;
    border-right: 1px solid #E2E8F0;
}
QFrame#TopBar {
    background-color: #FFFFFF;
    border-bottom: 1px solid #E2E8F0;
}
QFrame#SurfaceCard {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
}
QPushButton#NavButton {
    background-color: transparent;
    color: #475569;
    border: none;
    border-radius: 6px;
    padding: 9px 12px;
    text-align: left;
    font-weight: 500;
}
QPushButton#NavButton:hover {
    background-color: #F1F5F9;
    color: #0F172A;
}
QPushButton#NavButton[active="true"] {
    background-color: #1D4ED8;
    color: #FFFFFF;
    font-weight: 600;
}
QPushButton#PrimaryButton {
    background-color: #2563EB;
    color: #FFFFFF;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton#PrimaryButton:hover {
    background-color: #1D4ED8;
}
QPushButton#SecondaryButton {
    background-color: #FFFFFF;
    color: #0F172A;
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton#SecondaryButton:hover {
    background-color: #F1F5F9;
}
QLineEdit, QComboBox {
    background-color: #FFFFFF;
    color: #0F172A;
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 8px 10px;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #2563EB;
}
QTableWidget {
    background-color: #FFFFFF;
    alternate-background-color: #F8FAFC;
    gridline-color: #E2E8F0;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
}
QHeaderView::section {
    background-color: #F1F5F9;
    color: #475569;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #E2E8F0;
    font-weight: 600;
}
"""


def get_stylesheet(theme: str) -> str:
    return LIGHT_QSS if theme == "light" else DARK_QSS
