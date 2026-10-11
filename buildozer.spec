[app]
title = F1 Telemetry Dashboard
package.name = f1telemetry
package.domain = org.f1dash
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,html
version = 1.09
requirements = python3
orientation = landscape
fullscreen = 1
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WAKE_LOCK
android.api = 33
android.minapi = 21
android.ndk = 25b
android.ndk_api = 21
android.accept_sdk_license = True
android.archs = arm64-v8a
android.allow_backup = True
p4a.bootstrap = webview
p4a.port = 5000

[buildozer]
log_level = 2
warn_on_root = 1
