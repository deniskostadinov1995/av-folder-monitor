@echo off
rem Starts AV Folder Monitor without a console window.
cd /d "%~dp0"
start "" pythonw avg_monitor.py
