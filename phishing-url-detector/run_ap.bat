@echo off
cd /d "%~dp0"
title Phishing URL Detector

echo Checking requirements...
pip install -r requirements.txt

echo Launching browser...
start http://127.0.0.1:5000

echo Starting Python server...
python app.py

pause