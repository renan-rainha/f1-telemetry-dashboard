[app]
title = F1 Telemetry Dashboard
package.name = f1telemetry
package.domain = org.f1dash
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,html
version = 1.09
requirements = python3,kivy,pyjnius
orientation = landscape
fullscreen = 1
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK
android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = True

[buildozer]
log_level = 2
warn_on_root = 1
