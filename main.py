# main.py
import customtkinter as ctk
import database.db_session as db_session
from ui.dashboard import CyberGuardDashboard

if __name__ == "__main__":
    db_session.global_init()
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = CyberGuardDashboard()
    app.mainloop()