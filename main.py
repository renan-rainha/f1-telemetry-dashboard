# ==========================================
# SNIFFER EM TEMPO REAL DE TODOS OS BYTES UDP
# ==========================================
raw_prev_buffers = {
    "p6": None, # CarTelemetryData (60 bytes)
    "p7": None, # CarStatusData (59 bytes)
    "p2": None, # LapData (57 bytes)
}

# Histórico de eventos e alterações recentes
sniffer_recent_changes = []
active_changed_bytes = {
    "p6": {}, # {byte_index: current_value}
    "p7": {}, # {byte_index: current_value}
    "p2": {}, # {byte_index: current_value}
}
last_event_code = "NENHUM"


# ==========================================
# SCANNER DIAGNÓSTICO DE SAÍDAS UDP (MODO S)
# ==========================================
udp_scanner = {
    # Canais do Pacote 6 (Telemetria do Carro do Jogador)
    "CAN_01_P6_Clutch_B14": 0,
    "CAN_02_P6_DRS_B18": 0,
    "CAN_03_P6_RevBit_B20": 0,
    "CAN_04_P6_RevBit_B21": 0,
    "CAN_05_P6_EngineTemp_B38": 0,
    "CAN_06_P6_SurfaceType_B56": 0,
    "CAN_07_P6_Tail_ByteMinus5": 0,
    "CAN_08_P6_Tail_ByteMinus4": 0,
    "CAN_09_P6_Tail_ByteMinus3": 0,
    "CAN_10_P6_Tail_ByteMinus2": 0,

    # Canais do Pacote 7 (Status do Carro do Jogador)
    "CAN_11_P7_TC_B0": 0,
    "CAN_12_P7_ABS_B1": 0,
    "CAN_13_P7_FuelMix_B2": 0,
    "CAN_14_P7_MaxGears_B21": 0,
    "CAN_15_P7_DRS_Allowed_B22": 0,
    "CAN_16_P7_DRS_Dist_B23_24": 0,
    "CAN_17_P7_DRS_Disabled_B25": 0,
    "CAN_18_P7_ActualTyre_B26": 0,
    "CAN_19_P7_NetworkPaused_B55": 0,
    "CAN_20_P7_Extra_B56": 0,
    "CAN_21_P7_Extra_B57": 0,
    "CAN_22_P7_Extra_B58": 0,

    # Canais do Pacote 10 (Danos do Jogador)
    "CAN_23_P10_DRS_Fault_B30": 0,
    "CAN_24_P10_ERS_Fault_B31": 0,
}

# ==========================================
# CONTROLE DE VERSÃO DO SISTEMA
# ==========================================
APP_VERSION = "v1.09"

import socket
import struct
import threading
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

# ==========================================
# FUNÇÃO PARA DETECTAR O IP LOCAL DO APARELHO
# ==========================================
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = '127.0.0.1'
    finally:
        s.close()
    return ip

LOCAL_IP = get_local_ip()

# ==========================================
# TABELAS OFICIAIS F1: PILOTOS, EQUIPES E PNEUS
# ==========================================
TEAMS = {
    0: ("Mercedes", "#00d2be"),
    1: ("Ferrari", "#e8002d"),
    2: ("Red Bull", "#3671c6"),
    3: ("Williams", "#64c4ff"),
    4: ("Aston Martin", "#229971"),
    5: ("Alpine", "#ff87bc"),
    6: ("RB Honda", "#6692ff"),
    7: ("Haas", "#b6babd"),
    8: ("McLaren", "#ff8000"),
    9: ("Sauber", "#52e252"),
    85: ("Mercedes", "#00d2be"),
    86: ("Ferrari", "#e8002d"),
    87: ("Red Bull", "#3671c6"),
    88: ("McLaren", "#ff8000"),
    89: ("Aston Martin", "#229971"),
    90: ("Alpine", "#ff87bc"),
    91: ("RB Honda", "#6692ff"),
    92: ("Sauber", "#52e252"),
    93: ("Haas", "#b6babd"),
    94: ("Williams", "#64c4ff"),
}

# Mapeamento Oficial da Temporada 2025 / 2026: Garante cores e escuderias corretas mesmo em pacotes customizados
DRIVER_TEAMS_2026 = {
    "LECLERC": ("Ferrari", "#e8002d"),
    "HAMILTON": ("Ferrari", "#e8002d"),
    "NORRIS": ("McLaren", "#ff8000"),
    "PIASTRI": ("McLaren", "#ff8000"),
    "VERSTAPPEN": ("Red Bull", "#3671c6"),
    "PEREZ": ("Red Bull", "#3671c6"),
    "RUSSELL": ("Mercedes", "#00d2be"),
    "ANTONELLI": ("Mercedes", "#00d2be"),
    "ALONSO": ("Aston Martin", "#229971"),
    "STROLL": ("Aston Martin", "#229971"),
    "GASLY": ("Alpine", "#ff87bc"),
    "DOOHAN": ("Alpine", "#ff87bc"),
    "SAINZ": ("Williams", "#64c4ff"),
    "ALBON": ("Williams", "#64c4ff"),
    "COLAPINTO": ("Alpine", "#ff87bc"),
    "SARGEANT": ("Williams", "#64c4ff"),
    "TSUNODA": ("RB Honda", "#6692ff"),
    "LAWSON": ("RB Honda", "#6692ff"),
    "HADJAR": ("RB Honda", "#6692ff"),
    "RICCIARDO": ("RB Honda", "#6692ff"),
    "HULKENBERG": ("Sauber", "#52e252"),
    "BORTOLETO": ("Sauber", "#52e252"),
    "BOTTAS": ("Sauber", "#52e252"),
    "ZHOU": ("Sauber", "#52e252"),
    "OCON": ("Haas", "#b6babd"),
    "BEARMAN": ("Haas", "#b6babd"),
    "MAGNUSSEN": ("Haas", "#b6babd"),
}

DRIVERS = {
    0: "Carlos Sainz",
    2: "Daniel Ricciardo",
    3: "Fernando Alonso",
    7: "Lewis Hamilton",
    9: "Max Verstappen",
    10: "Nico Hulkenberg",
    11: "Kevin Magnussen",
    14: "Sergio Perez",
    15: "Valtteri Bottas",
    17: "Esteban Ocon",
    19: "Lance Stroll",
    50: "George Russell",
    54: "Lando Norris",
    58: "Charles Leclerc",
    59: "Pierre Gasly",
    62: "Alexander Albon",
    80: "Guanyu Zhou",
    94: "Yuki Tsunoda",
    112: "Oscar Piastri",
    113: "Liam Lawson",
    132: "Logan Sargeant",
    136: "Jack Doohan",
    147: "Oliver Bearman",
    149: "Isack Hadjar",
    159: "Andrea Antonelli",
    160: "Franco Colapinto",
    161: "Gabriel Bortoleto",
}

TYRE_MAP = {
    16: ("S", "MACIO", "#ef4444"),
    17: ("M", "MÉDIO", "#eab308"),
    18: ("H", "DURO", "#f8fafc"),
    7:  ("I", "INTER", "#22c55e"),
    8:  ("W", "CHUVA", "#38bdf8")
}

ERS_MODES = {0: "NONE", 1: "MED", 2: "HOTLAP", 3: "OVERTAKE"}

# ==========================================
# ESTADO GLOBAL DA TELEMETRIA
# ==========================================
telemetry = {
    "connected": False,
    "version": APP_VERSION,
    "local_ip": LOCAL_IP,
    "speed": 0,
    "gear": 0,
    "suggested_gear": 0,
    "rpm": 0,
    "max_rpm": 13500,
    "rev_lights_pct": 0,
    "drs": 0,
    "drs_allowed": 0,
    "ers_pct": 100.0,
    "ers_mode": "MED",
    "fuel_delta": 0.0,
    "brake_bias": 56.0,
    "lap_time": "0:00.000",
    "last_lap": "0:00.000",
    "delta": 0.0,
    "delta_type": "lap",
    "position": 1,
    "total_cars": 22,
    "lap_num": 1,
    "total_laps": 1,
    "track_length": 5000,
    "safety_car": 0,
    "sc_delta": 0.0,
    "flag": 0,
    "pit_rejoin_pos": 1,
    "in_pit": False,
    "tyres": {
        "compound": "M",
        "compound_color": "#eab308",
        "age": 0,
        "fl_wear": 0, "fr_wear": 0, "rl_wear": 0, "rr_wear": 0,
        "fl_temp": 100, "fr_temp": 100, "rl_temp": 100, "rr_temp": 100
    },
    "wing_damage": {
        "fl": 0,
        "fr": 0
    },
    "weather": {
        "rain_5m": 0,
        "rain_10m": 0
    },
    "leaderboard": [],
    "cars_gps": [],
    "track_shape": [],
    "scanner": udp_scanner,
    "sniffer_log": sniffer_recent_changes,
    "p6_bytes": active_changed_bytes["p6"],
    "p7_bytes": active_changed_bytes["p7"],
    "last_event": last_event_code
}

# Controle de Identificação da Sessão para Reset Automático de Tempos
session_tracker = {
    "uid": 0,
    "last_time": 0.0
}

def reset_session_data():
    """Limpa todos os tempos e dados ao reiniciar ou trocar de sessão no jogo."""
    global track_bins
    track_bins = [None] * 100
    telemetry["track_shape"] = []
    telemetry["leaderboard"] = []
    telemetry["lap_time"] = "0:00.000"
    telemetry["last_lap"] = "0:00.000"
    telemetry["delta"] = 0.0

    live_delta_tracker["ref_timeline"].clear()
    live_delta_tracker["current_timeline"].clear()
    live_delta_tracker["current_lap_num"] = 0
    live_delta_tracker["last_delta_val"] = 0.0

    player_pace["last_ms"] = 0
    player_pace["best_ms"] = 0
    player_pace["delta"] = 0.0
    player_pace["current_recorded_last"] = 0

    for i in range(len(cars_info)):
        cars_info[i]["best_lap_ms"] = 0
        cars_info[i]["last_lap"] = "0:00.000"
        cars_info[i]["gap"] = "-"


# Armazenamento contínuo de perfil de volta para cálculo de Delta em tempo real (milissegundo a milissegundo)
live_delta_tracker = {
    "ref_timeline": {},       # {bin_distance_10m: time_ms} da melhor volta / volta de referência
    "current_timeline": {},   # {bin_distance_10m: time_ms} da volta atual em andamento
    "current_lap_num": 0,
    "last_delta_val": 0.0
}

player_pace = {
    "last_ms": 0,
    "best_ms": 0,
    "delta": 0.0,
    "current_recorded_last": 0
}

cars_info = [{"name": f"Piloto {i+1}", "team": "F1 Team", "color": "#38bdf8", "compound": "M", "compound_color": "#eab308", "pos": i+1, "last_lap": "0:00.000", "gap": "LÍDER" if i==0 else "+0.000s", "x": 0.0, "z": 0.0, "lap_dist": 0.0, "best_lap_ms": 0} for i in range(24)]

# Grade de 100 setores para construção matemática do circuito
track_bins = [None] * 100

def get_interpolated_track():
    pts = list(track_bins)
    n = len(pts)
    first_idx = next((i for i, p in enumerate(pts) if p is not None), None)
    if first_idx is None:
        return []
    
    last_valid = pts[first_idx]
    last_idx = first_idx
    for i in range(first_idx + 1, n + first_idx):
        idx = i % n
        if pts[idx] is None:
            next_idx = None
            for j in range(i + 1, i + n):
                if pts[j % n] is not None:
                    next_idx = j % n
                    break
            if next_idx is not None:
                steps = (next_idx - last_idx) % n
                curr_step = (idx - last_idx) % n
                factor = curr_step / steps
                x0, z0 = last_valid
                x1, z1 = pts[next_idx]
                pts[idx] = (round(x0 + (x1 - x0) * factor, 1), round(z0 + (z1 - z0) * factor, 1))
        else:
            last_valid = pts[idx]
            last_idx = idx
    return [p for p in pts if p is not None]

# ==========================================
# INTERFACE HTML/CSS/JS (CIRCUITO DESENHADO E CARROS NUMERADOS)
# ==========================================
HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#08090d">
<link rel="manifest" href="data:application/manifest+json,%7B%22name%22%3A%22F1%20Dashboard%22%2C%22short_name%22%3A%22F1%20Dash%22%2C%22display%22%3A%22fullscreen%22%2C%22orientation%22%3A%22landscape%22%2C%22start_url%22%3A%22%2F%22%2C%22background_color%22%3A%22%2308090d%22%2C%22theme_color%22%3A%22%2308090d%22%7D">
<title>F1 Telemetry Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; user-select: none; -webkit-user-select: none; -webkit-touch-callout: none; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  
  body {
    background: radial-gradient(circle at center, #141724 0%, #08090d 100%);
    background-color: #08090d;
    color: #fff;
    width: 100vw;
    height: 100vh;
    height: 100dvh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 6px 14px 10px 14px;
    position: relative;
  }

  /* POPUP DO IP */
  .hud-popup-overlay {
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    z-index: 2500;
    background: rgba(8, 10, 15, 0.94);
    display: none;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(5px);
  }
  .hud-popup-overlay.active { display: flex; }
  .hud-popup-box {
    background: #0f131e;
    border: 2px solid #38bdf8;
    border-radius: 18px;
    padding: 24px 36px;
    text-align: center;
    box-shadow: 0 0 35px rgba(56, 189, 248, 0.35);
  }
  .hud-popup-title { font-size: 13px; font-weight: 900; color: #94a3b8; letter-spacing: 1px; margin-bottom: 6px; text-transform: uppercase; }
  .hud-popup-ip { font-size: 52px; font-weight: 900; color: #38bdf8; font-variant-numeric: tabular-nums; text-shadow: 0 0 18px rgba(56, 189, 248, 0.6); margin-bottom: 8px; }
  .hud-popup-sub { font-size: 15px; font-weight: 800; color: #f1f5f9; margin-bottom: 8px; }
  .hud-popup-hint { font-size: 11px; font-weight: 900; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }

  /* BANNER TEMPORÁRIO DE BANDEIRAS */
  .flag-flash-overlay {
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    z-index: 2000;
    display: none;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    animation: flash-border 0.4s infinite alternate;
  }
  .flag-flash-overlay.active { display: flex; }
  .flag-flash-icon { font-size: 80px; margin-bottom: 8px; }
  .flag-flash-title { font-size: 42px; font-weight: 900; letter-spacing: 2px; text-transform: uppercase; }
  .flag-flash-subtitle { font-size: 20px; font-weight: 800; opacity: 0.9; margin-top: 4px; }

  @keyframes flash-border {
    0% { opacity: 0.92; transform: scale(1); }
    100% { opacity: 1; transform: scale(1.02); }
  }

  .version-badge {
    position: absolute;
    top: 6px;
    left: 10px;
    z-index: 999;
    background: rgba(18, 22, 32, 0.85);
    border: 1px solid #334155;
    color: #64748b;
    font-size: 9px;
    font-weight: 800;
    padding: 2px 7px;
    border-radius: 10px;
    letter-spacing: 0.5px;
  }

    /* SCANNER DIAGNÓSTICO DE SAÍDAS UDP */
  #scannerModal {
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(8, 10, 16, 0.96);
    z-index: 3000;
    display: none;
    flex-direction: column;
    padding: 10px 14px;
    backdrop-filter: blur(8px);
  }
  #scannerModal.active { display: flex; }
  .scanner-header-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #0f1422;
    border: 1.5px solid #38bdf8;
    border-radius: 10px;
    padding: 6px 14px;
    margin-bottom: 8px;
  }
  .scanner-title { font-size: 14px; font-weight: 900; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; }
  .scanner-close-btn { background: #dc2626; color: #fff; font-size: 11px; font-weight: 900; border: none; padding: 4px 12px; border-radius: 6px; cursor: pointer; }
  .scanner-clear-btn { background: #0284c7; color: #fff; font-size: 11px; font-weight: 900; border: none; padding: 4px 12px; border-radius: 6px; cursor: pointer; }
  .sniffer-log-panel-fullscreen {
    flex: 1;
    background: #090d16;
    border: 1.5px solid #1e293b;
    border-radius: 10px;
    padding: 8px 12px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .sniffer-log-title { font-size: 12px; font-weight: 900; color: #f59e0b; margin-bottom: 6px; letter-spacing: 0.5px; text-transform: uppercase; }
  .sniffer-log-list-fullscreen {
    flex: 1;
    overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    font-weight: 700;
    color: #22c55e;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-right: 4px;
  }
  .sniffer-log-entry {
    background: rgba(34, 197, 94, 0.08);
    border: 1px solid rgba(34, 197, 94, 0.25);
    border-left: 4px solid #22c55e;
    padding: 4px 8px;
    border-radius: 4px;
    line-height: 1.25;
  }

.fs-btn {
    position: absolute;
    top: 6px;
    right: 10px;
    z-index: 999;
    background: rgba(18, 22, 32, 0.85);
    border: 1px solid #38bdf8;
    color: #38bdf8;
    font-size: 10px;
    font-weight: 800;
    padding: 3px 8px;
    border-radius: 12px;
    cursor: pointer;
  }

  /* 1. SHIFT LIGHTS */
  .top-leds-bar {
    width: 100%;
    display: flex;
    justify-content: center;
    margin-bottom: 2px;
  }

  .leds-container {
    background: #0e1118;
    border: 1.5px solid #232838;
    border-radius: 20px;
    padding: 6px 16px;
    display: flex;
    width: 88%;
    max-width: 820px;
    justify-content: space-between;
    box-shadow: inset 0 2px 5px rgba(0,0,0,0.8), 0 4px 12px rgba(0,0,0,0.6);
  }

  .led {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #1a1e2a;
    box-shadow: inset 0 1px 3px rgba(0,0,0,0.9);
    transition: all 0.04s ease;
  }

  .led.green.on { background: #00ff55; box-shadow: 0 0 14px #00ff55, inset 0 0 4px #fff; }
  .led.red.on   { background: #ff2222; box-shadow: 0 0 14px #ff2222, inset 0 0 4px #fff; }
  .led.blue.on  { background: #a824ff; box-shadow: 0 0 16px #a824ff, inset 0 0 4px #fff; }

  /* 2. LINHA SUPERIOR DE STATUS */
  .top-info-row {
    display: grid;
    grid-template-columns: 28% 44% 28%;
    align-items: center;
    width: 100%;
    margin-bottom: 2px;
  }

  .rain-box { display: flex; flex-direction: column; gap: 2px; padding-left: 8px; }
  .rain-line { font-size: 15px; font-weight: 800; color: #e2e8f0; display: flex; gap: 10px; }
  .rain-val { color: #38bdf8; }

  .speed-center {
    display: flex;
    justify-content: center;
    align-items: baseline;
    gap: 6px;
    cursor: pointer;
  }
  .speed-num { font-size: 52px; font-weight: 900; letter-spacing: -2px; color: #ffffff; text-shadow: 0 0 20px rgba(255,255,255,0.25); line-height: 52px; }
  .speed-unit { font-size: 15px; font-weight: 800; color: #94a3b8; }

  .session-box { display: flex; flex-direction: column; align-items: flex-end; padding-right: 8px; }
  .pos-text { font-size: 26px; font-weight: 900; color: #fff; line-height: 26px; }
  .lap-text { font-size: 15px; font-weight: 800; color: #94a3b8; margin-top: 2px; }

  /* 3. ÁREA CENTRAL */
  .main-center-row {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 29% 42% 29%;
    gap: 12px;
    align-items: center;
  }

  .tyre-panel-card {
    background: rgba(14, 18, 26, 0.75);
    border: 1.5px solid #222838;
    border-radius: 14px;
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    height: 100%;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    cursor: pointer;
    touch-action: none;
  }
  .tyre-panel-card:active { border-color: #38bdf8; background: rgba(20, 26, 38, 0.9); }

  .tyre-content-flex { display: flex; align-items: center; justify-content: space-around; flex: 1; }
  .tyre-graphic-wrap { width: 52px; height: 86px; flex-shrink: 0; }
  .tyre-numbers-block { display: flex; flex-direction: column; gap: 6px; }
  .tyre-stat-group { display: flex; flex-direction: column; line-height: 1.1; }
  .tyre-pos-title { font-size: 12px; font-weight: 900; color: #cbd5e1; }
  .tyre-temp-num { font-size: 15px; font-weight: 900; }
  .tyre-wear-num { font-size: 13px; font-weight: 800; color: #f59e0b; }

  .wing-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0f121a;
    padding: 3px 8px;
    border-radius: 6px;
    border: 1px solid #1f2535;
    margin-top: 4px;
  }
  .wing-dot { width: 5px; height: 16px; border-radius: 2px; background: #22c55e; flex-shrink: 0; }
  .wing-label { font-size: 12px; font-weight: 900; color: #fff; }

  .rejoin-subcard { text-align: right; font-size: 12px; font-weight: 900; color: #f59e0b; margin-top: 3px; padding-right: 2px; text-transform: uppercase; letter-spacing: 0.5px; }

  .cockpit-center { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; }
  .gear-and-systems { display: flex; align-items: center; justify-content: center; gap: 14px; width: 100%; }

  .drs-vertical-box {
    background: #11141c;
    border: 1.5px solid #23293a;
    border-radius: 8px;
    width: 60px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: 0 4px 10px rgba(0,0,0,0.5);
    transition: all 0.1s ease;
  }
  .drs-header { font-size: 11px; font-weight: 900; text-align: center; padding: 3px 0; color: #64748b; background: #131722; }
  .drs-status { font-size: 15px; font-weight: 900; text-align: center; padding: 4px 0; background: #1a202c; color: #64748b; }
  .drs-vertical-box.off .drs-header { color: #64748b; background: #131722; }
  .drs-vertical-box.off .drs-status { background: #1a202c; color: #64748b; }
  .drs-vertical-box.avail { border-color: #f59e0b; box-shadow: 0 0 12px rgba(245,158,11,0.5); }
  .drs-vertical-box.avail .drs-header { color: #f59e0b; background: #261b07; }
  .drs-vertical-box.avail .drs-status { background: #f59e0b; color: #000; font-weight: 900; }
  .drs-vertical-box.on-active { border-color: #00ff55; box-shadow: 0 0 16px rgba(0,255,85,0.7); }
  .drs-vertical-box.on-active .drs-header { color: #00ff55; background: #072912; }
  .drs-vertical-box.on-active .drs-status { background: #00ff55; color: #000; font-weight: 900; text-shadow: none; }

  .gear-column { display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .gear-number { font-size: 150px; font-weight: 900; line-height: 115px; color: #ffffff; text-shadow: 0 0 25px rgba(255,255,255,0.25); }
  .sugg-gear-pill {
    background: #0f1d38;
    border: 1.5px solid #2563eb;
    border-radius: 20px;
    padding: 3px 16px;
    font-size: 13px;
    font-weight: 900;
    color: #60a5fa;
    margin-top: 4px;
    box-shadow: 0 0 10px rgba(37,99,235,0.4);
    display: block;
  }

  .right-systems-stack { display: flex; flex-direction: column; gap: 8px; width: 72px; }
  .sys-badge { border-radius: 7px; padding: 3px 6px; display: flex; flex-direction: column; align-items: center; border: 1.5px solid #23293a; }
  .sys-badge.ers-box { background: #0c182c; border-color: #0284c7; }
  .sys-badge.fuel-box { background: #241c08; border-color: #eab308; }
  .sys-title { font-size: 10px; font-weight: 900; }
  .ers-box .sys-title { color: #bae6fd; }
  .ers-box .sys-val { color: #38bdf8; font-size: 13px; font-weight: 900; }
  .ers-box .sys-mode { color: #60a5fa; font-size: 10px; font-weight: 800; }
  .fuel-box .sys-title { color: #fef08a; }
  .fuel-box .sys-val { color: #facc15; font-size: 13px; font-weight: 900; }

  /* 4. BARRA INFERIOR */
  .bottom-timing-row {
    background: #0a0d14;
    border: 1.5px solid #1f2536;
    border-radius: 12px;
    height: 48px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    box-shadow: inset 0 2px 6px rgba(0,0,0,0.8);
    width: 100%;
  }

  .timing-block { display: flex; align-items: baseline; gap: 6px; }
  .timing-title { font-size: 12px; font-weight: 900; color: #e2e8f0; letter-spacing: 0.5px; }
  .lap-yellow { font-size: 19px; font-weight: 900; color: #facc15; font-variant-numeric: tabular-nums; }
  .delta-neon { font-size: 24px; font-weight: 900; color: #00ff55; text-shadow: 0 0 14px rgba(0,255,85,0.4); }
  .last-white { font-size: 19px; font-weight: 900; color: #ffffff; font-variant-numeric: tabular-nums; }

  .sc-override-banner { display: none; width: 100%; height: 100%; align-items: center; justify-content: center; gap: 20px; font-weight: 900; border-radius: 8px; }
  .sc-override-banner.active { display: flex; animation: sc-pulse 1s infinite alternate; }
  .sc-title { font-size: 18px; }
  .sc-delta-val { font-size: 22px; padding: 2px 14px; border-radius: 6px; }
  .sc-delta-val.safe { background: #00ff55; color: #000; }
  .sc-delta-val.danger { background: #ef4444; color: #fff; }

  @keyframes sc-pulse { 0% { background: #ca8a04; color: #000; } 100% { background: #a16207; color: #000; } }
  .vsc-pulse-anim { animation: vsc-pulse 1s infinite alternate !important; }
  @keyframes vsc-pulse { 0% { background: #ea580c; color: #fff; } 100% { background: #9a3412; color: #fff; } }

  /* TELA DO BOX / GARAGEM (AO VIVO) */
  #garageScreen {
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    background: #090b10;
    z-index: 1500;
    display: none;
    flex-direction: column;
    padding: 10px 14px;
  }
  #garageScreen.active { display: flex; }

  .garage-header-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #111520;
    border: 1.5px solid #232a3d;
    border-radius: 10px;
    padding: 6px 14px;
    margin-bottom: 8px;
  }

  .garage-title-tag {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 900;
    color: #f59e0b;
    text-transform: uppercase;
  }
  .garage-pulse-dot {
    width: 10px; height: 10px; border-radius: 50%; background: #f59e0b;
    box-shadow: 0 0 10px #f59e0b;
    animation: garage-dot 0.8s infinite alternate;
  }
  @keyframes garage-dot { 0% { opacity: 0.4; } 100% { opacity: 1; } }

  .garage-grid {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 46% 54%;
    gap: 12px;
  }

  .track-map-card {
    background: #0f131c;
    border: 1.5px solid #202738;
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    padding: 8px;
    overflow: hidden;
    position: relative;
  }
  .track-card-header { font-size: 11px; font-weight: 900; color: #8fa0be; text-transform: uppercase; margin-bottom: 4px; display: flex; justify-content: space-between; }
  #trackCanvas { flex: 1; width: 100%; height: 100%; border-radius: 8px; background: #07090f; }

  .leaderboard-card {
    background: #0f131c;
    border: 1.5px solid #202738;
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    padding: 8px;
    overflow: hidden;
  }
  .table-scroll-wrap { flex: 1; overflow-y: auto; margin-top: 4px; }
  
  .lb-table { width: 100%; border-collapse: collapse; font-size: 12px; font-weight: 800; table-layout: fixed; }
  .lb-table th { color: #64748b; text-align: left; padding: 4px 4px; font-size: 10px; border-bottom: 1.5px solid #23293d; position: sticky; top: 0; background: #0f131c; }
  .lb-table td { padding: 4px 4px; border-bottom: 1px solid #1a202e; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  
  .col-pos { width: 38px; text-align: center; }
  .col-driver { width: auto; }
  .col-tyre { width: 34px; text-align: center; }
  .col-time { width: 75px; text-align: right; }
  .col-gap { width: 68px; text-align: right; }

  .lb-row.player-row { background: #162a45; border-left: 3px solid #38bdf8; }
  .lb-row.player-row td { color: #38bdf8; }
  .tyre-chip { padding: 1px 4px; border-radius: 3px; font-size: 10px; font-weight: 900; color: #000; display: inline-block; width: 18px; text-align: center; }
</style>
</head>
<body>

  <!-- POPUP DO IP (SEGURE O PNEU ESQUERDO) -->
  <div class="hud-popup-overlay" id="ipOverlay">
    <div class="hud-popup-box">
      <div class="hud-popup-title">Endereço IP do Dispositivo</div>
      <div class="hud-popup-ip" id="ipValue">127.0.0.1</div>
      <div class="hud-popup-sub">Digite este IP no F1 25 do Xbox (Porta 20777)</div>
      <div class="hud-popup-hint">Solte o dedo para fechar</div>
    </div>
  </div>

  <!-- BANNER TEMPORÁRIO DE BANDEIRAS -->
  <div class="flag-flash-overlay" id="flagFlash">
    <div class="flag-flash-icon" id="flashIcon">⚠️</div>
    <div class="flag-flash-title" id="flashTitle">BANDEIRA AMARELA</div>
    <div class="flag-flash-subtitle" id="flashSubtitle">REDUZA A VELOCIDADE</div>
  </div>

  <!-- VERSÃO DO SISTEMA -->
  <div class="version-badge" id="versionBadge">v1.09</div>

  <!-- BOTÃO SCANNER DIAGNÓSTICO UDP -->
  <div class="fs-btn" style="right: 100px; border-color: #f59e0b; color: #f59e0b;" onclick="openScanner()">🔍 SCANNER MODO S</div>

  <!-- BOTÃO TELA CHEIA -->
  <div class="fs-btn" id="fsBtn" onclick="toggleFS()">⛶ TELA CHEIA</div>

  <!-- 1. SHIFT LIGHTS -->
  <div class="top-leds-bar">
    <div class="leds-container" id="ledsContainer"></div>
  </div>

  <!-- 2. LINHA SUPERIOR -->
  <div class="top-info-row">
    <div class="rain-box">
      <div class="rain-line"><span>+5 min</span><span class="rain-val" id="rain5">0%</span></div>
      <div class="rain-line"><span>+10 min</span><span class="rain-val" id="rain10">0%</span></div>
    </div>

    <!-- CLIQUE NA VELOCIDADE ALTERNA TELA CHEIA -->
    <div class="speed-center" id="speedClick">
      <div class="speed-num" id="speed">0</div>
      <div class="speed-unit">KM/H</div>
    </div>

    <div class="session-box">
      <div class="pos-text" id="pos">P1/22</div>
      <div class="lap-text" id="lap">Volta 1/1</div>
    </div>
  </div>

  <!-- 3. ÁREA CENTRAL -->
  <div class="main-center-row">
    <!-- PNEU ESQUERDO (SEGURE PARA VER O IP) -->
    <div class="tyre-panel-card" id="leftTyreCard">
      <div class="tyre-content-flex">
        <div class="tyre-graphic-wrap">
          <svg viewBox="0 0 60 90" width="100%" height="100%">
            <defs>
              <linearGradient id="rubberGradL" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stop-color="#14171f"/>
                <stop offset="25%" stop-color="#2c3240"/>
                <stop offset="55%" stop-color="#1a1d26"/>
                <stop offset="85%" stop-color="#101217"/>
                <stop offset="100%" stop-color="#08090d"/>
              </linearGradient>
              <radialGradient id="rimGradL" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stop-color="#2a2e3b"/>
                <stop offset="70%" stop-color="#12141a"/>
                <stop offset="100%" stop-color="#08090c"/>
              </radialGradient>
            </defs>
            <rect x="4" y="3" width="52" height="84" rx="14" fill="url(#rubberGradL)" stroke="#262b3a" stroke-width="1.5"/>
            <ellipse cx="32" cy="45" rx="16" ry="32" fill="none" stroke="#eab308" stroke-width="4.5" id="tyreRingL"/>
            <ellipse cx="33" cy="45" rx="11" ry="24" fill="url(#rimGradL)"/>
            <circle cx="33" cy="45" r="4" fill="#475569"/>
          </svg>
        </div>

        <div class="tyre-numbers-block">
          <div class="tyre-stat-group">
            <span class="tyre-pos-title">DE</span>
            <span class="tyre-temp-num" id="flTemp" style="color:#22c55e;">100°C</span>
            <span class="tyre-wear-num" id="flWear">0%</span>
          </div>
          <div class="tyre-stat-group" style="margin-top:4px;">
            <span class="tyre-pos-title">TE</span>
            <span class="tyre-temp-num" id="rlTemp" style="color:#22c55e;">100°C</span>
            <span class="tyre-wear-num" id="rlWear">0%</span>
          </div>
        </div>
      </div>

      <div class="wing-strip">
        <div class="wing-dot" id="flWingDot"></div>
        <span class="wing-label" id="flWingText">ASA ESQ: 0%</span>
      </div>
    </div>

    <!-- CENTRO -->
    <div class="cockpit-center">
      <div class="gear-and-systems">
        <div class="drs-vertical-box" id="drsBox" onclick="toggleModoSTest()" title="Clique para testar Modo S">
          <div class="drs-header" id="drsHeader">MODO S</div>
          <div class="drs-status" id="drsStatus">OFF</div>
        </div>

        <div class="gear-column">
          <div class="gear-number" id="gear">N</div>
          <div class="sugg-gear-pill" id="suggGear">PRÓXIMA: -</div>
        </div>

        <div class="right-systems-stack">
          <div class="sys-badge ers-box">
            <span class="sys-title">ERS</span>
            <span class="sys-val" id="ersVal">100%</span>
            <span class="sys-mode" id="ersMode">MED</span>
          </div>
          <div class="sys-badge fuel-box">
            <span class="sys-title">FUEL</span>
            <span class="sys-val" id="fuelVal">+0.00</span>
          </div>
        </div>
      </div>
    </div>

    <!-- PNEU DIREITO (SEGURE PARA VER O BOX) -->
    <div class="tyre-panel-card" id="rightTyreCard">
      <div class="tyre-content-flex">
        <div class="tyre-numbers-block" style="text-align:right;">
          <div class="tyre-stat-group">
            <span class="tyre-pos-title">DD</span>
            <span class="tyre-temp-num" id="frTemp" style="color:#22c55e;">100°C</span>
            <span class="tyre-wear-num" id="frWear">0%</span>
          </div>
          <div class="tyre-stat-group" style="margin-top:4px;">
            <span class="tyre-pos-title">TD</span>
            <span class="tyre-temp-num" id="rrTemp" style="color:#22c55e;">100°C</span>
            <span class="tyre-wear-num" id="rrWear">0%</span>
          </div>
        </div>

        <div class="tyre-graphic-wrap">
          <svg viewBox="0 0 60 90" width="100%" height="100%">
            <defs>
              <linearGradient id="rubberGradR" x1="100%" y1="0%" x2="0%" y2="0%">
                <stop offset="0%" stop-color="#14171f"/>
                <stop offset="25%" stop-color="#2c3240"/>
                <stop offset="55%" stop-color="#1a1d26"/>
                <stop offset="85%" stop-color="#101217"/>
                <stop offset="100%" stop-color="#08090d"/>
              </linearGradient>
            </defs>
            <rect x="4" y="3" width="52" height="84" rx="14" fill="url(#rubberGradR)" stroke="#262b3a" stroke-width="1.5"/>
            <ellipse cx="28" cy="45" rx="16" ry="32" fill="none" stroke="#eab308" stroke-width="4.5" id="tyreRingR"/>
            <ellipse cx="27" cy="45" rx="11" ry="24" fill="url(#rimGradL)"/>
            <circle cx="27" cy="45" r="4" fill="#475569"/>
          </svg>
        </div>
      </div>

      <div class="wing-strip" style="justify-content:space-between;">
        <span class="wing-label" id="frWingText">ASA DIR: 0%</span>
        <div class="wing-dot" id="frWingDot"></div>
      </div>

      <div class="rejoin-subcard">
        Retorno do Box: <span id="pitRejoin" style="font-size:15px; font-weight:900; color:#fff;">P1</span>
      </div>
    </div>
  </div>

  <!-- 4. CRONOMETRAGEM BASE -->
  <div class="bottom-timing-row">
    <div class="timing-block normal-time-block" id="tb1">
      <span class="timing-title">VOLTA:</span>
      <span class="lap-yellow" id="lapTime">0:00.000</span>
    </div>

    <div class="timing-block normal-time-block" id="tb2">
      <span class="delta-neon" id="deltaVal">-0.000s</span>
    </div>

    <div class="timing-block normal-time-block" id="tb3">
      <span class="timing-title">ÚLTIMA:</span>
      <span class="last-white" id="lastLap">0:00.000</span>
    </div>

    <div class="sc-override-banner" id="scBanner">
      <span class="sc-title" id="scTitle">SAFETY CAR</span>
      <div class="sc-delta-val safe" id="scDelta">+0.000s</div>
    </div>
  </div>

  <!-- TELA DO BOX / GARAGEM (MAPA DA PISTA COM TRAÇADO REAL E CARROS NUMERADOS) -->
    <!-- TELA SNIFFER DIAGNÓSTICO DE DADOS (LISTA EXPANDIDA EM TELA CHEIA) -->
  <div id="scannerModal">
    <div class="scanner-header-bar">
      <div class="scanner-title">🔍 SNIFFER MODO S — LISTA COMPLETA DE EVENTOS E ALTERAÇÕES DE BYTES</div>
      <div style="display:flex; gap:8px;">
        <button class="scanner-clear-btn" onclick="clearSnifferLog()">LIMPAR REGISTRO ↺</button>
        <button class="scanner-close-btn" onclick="closeScanner()">FECHAR ✕</button>
      </div>
    </div>

    <div class="sniffer-log-panel-fullscreen">
      <div class="sniffer-log-title">📋 HISTÓRICO DE EVENTOS E SAÍDAS DIGITAIS (Mais recentes no topo — ideal para fotografar):</div>
      <div class="sniffer-log-list-fullscreen" id="snifferLogList">
        <div style="color:#64748b; font-style:italic; padding: 10px;">Aguardando dados da telemetria... Ao acionar o Modo S na pista, todas as mudanças aparecerão aqui em sequência!</div>
      </div>
    </div>
  </div>

  <div id="garageScreen">
    <div class="garage-header-bar">
      <div class="garage-title-tag">
        <div class="garage-pulse-dot"></div>
        <span>MODO GARAGEM / BOX</span>
      </div>
      <div style="font-size:12px; color:#cbd5e1; font-weight:800;">
        Retorna automaticamente ao cockpit ao sair do pit lane
      </div>
    </div>

    <div class="garage-grid">
      <div class="track-map-card">
        <div class="track-card-header">
          <span>Traçado do Circuito (Ao Vivo)</span>
          <span style="color:#00ff55;">● Você</span>
        </div>
        <canvas id="trackCanvas"></canvas>
      </div>

      <div class="leaderboard-card">
        <div class="track-card-header">
          <span>Classificação da Sessão</span>
          <span id="lbTotalCars">22 Carros</span>
        </div>
        <div class="table-scroll-wrap">
          <table class="lb-table">
            <thead>
              <tr>
                <th class="col-pos">POS</th>
                <th class="col-driver">PILOTO</th>
                <th class="col-tyre">PNEU</th>
                <th class="col-time">MELHOR</th>
                <th class="col-gap">GAP</th>
              </tr>
            </thead>
            <tbody id="lbBody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

<script>
  function toggleFS() {
    const el = document.documentElement;
    if (!document.fullscreenElement) {
      if (el.requestFullscreen) el.requestFullscreen().catch(() => {});
      else if (el.webkitRequestFullscreen) el.webkitRequestFullscreen();
    } else {
      if (document.exitFullscreen) document.exitFullscreen().catch(() => {});
    }
  }

  document.getElementById('speedClick').addEventListener('click', toggleFS);
  document.addEventListener('fullscreenchange', () => {
    const btn = document.getElementById('fsBtn');
    btn.style.display = document.fullscreenElement ? 'none' : 'block';
  });

  const leftCard = document.getElementById('leftTyreCard');
  const ipModal = document.getElementById('ipOverlay');

  function openIP(e) { if (e && e.cancelable) e.preventDefault(); ipModal.classList.add('active'); }
  function closeIP(e) { if (e && e.cancelable) e.preventDefault(); ipModal.classList.remove('active'); }

  leftCard.addEventListener('mousedown', openIP);
  leftCard.addEventListener('mouseup', closeIP);
  leftCard.addEventListener('mouseleave', closeIP);
  leftCard.addEventListener('touchstart', openIP, {passive: false});
  leftCard.addEventListener('touchend', closeIP, {passive: false});
  leftCard.addEventListener('touchcancel', closeIP, {passive: false});

  const rightCard = document.getElementById('rightTyreCard');
  const gScreen = document.getElementById('garageScreen');
  let isHoldingRight = false;
  let serverInPit = false;

  function openBoxHold(e) {
    if (e && e.cancelable) e.preventDefault();
    isHoldingRight = true;
    gScreen.classList.add('active');
  }
  function closeBoxHold(e) {
    if (e && e.cancelable) e.preventDefault();
    isHoldingRight = false;
    if (!serverInPit) {
      gScreen.classList.remove('active');
    }
  }

  rightCard.addEventListener('mousedown', openBoxHold);
  rightCard.addEventListener('mouseup', closeBoxHold);
  rightCard.addEventListener('mouseleave', closeBoxHold);
  rightCard.addEventListener('touchstart', openBoxHold, {passive: false});
  rightCard.addEventListener('touchend', closeBoxHold, {passive: false});
  rightCard.addEventListener('touchcancel', closeBoxHold, {passive: false});

  const ledsWrap = document.getElementById('ledsContainer');
  for (let i = 0; i < 15; i++) {
    const d = document.createElement('div');
    d.className = 'led ' + (i < 5 ? 'green' : i < 10 ? 'red' : 'blue');
    d.id = 'led_' + i;
    ledsWrap.appendChild(d);
  }

  function getTempHex(temp) {
    if (temp < 88) return '#38bdf8';
    if (temp <= 104) return '#22c55e';
    if (temp <= 112) return '#f59e0b';
    return '#ef4444';
  }

  function updateWing(dotId, textId, prefix, dmg) {
    const dot = document.getElementById(dotId);
    const txt = document.getElementById(textId);
    txt.textContent = prefix + ': ' + dmg + '%';
    if (dmg === 0) { dot.style.background = '#22c55e'; txt.style.color = '#fff'; }
    else if (dmg < 25) { dot.style.background = '#f59e0b'; txt.style.color = '#f59e0b'; }
    else { dot.style.background = '#ef4444'; txt.style.color = '#ef4444'; }
  }

  let lastFlag = 0;
  let lastSC = 0;
  let alertTimer = null;

  function triggerFlashAlert(icon, title, sub, bg, textCol) {
    const overlay = document.getElementById('flagFlash');
    overlay.style.background = bg;
    overlay.style.color = textCol;
    document.getElementById('flashIcon').textContent = icon;
    document.getElementById('flashTitle').textContent = title;
    document.getElementById('flashSubtitle').textContent = sub;
    overlay.classList.add('active');

    clearTimeout(alertTimer);
    alertTimer = setTimeout(() => {
      overlay.classList.remove('active');
    }, 2000);
  }

  // =========================================
  // RENDERIZADOR DO MAPA DA PISTA E CARROS
  // =========================================
  const canvas = document.getElementById('trackCanvas');
  const ctx = canvas.getContext('2d');
  let trackBounds = { minX: Infinity, maxX: -Infinity, minZ: Infinity, maxZ: -Infinity };

  function drawTrackAndCars(trackShape, cars) {
    if (canvas.width !== canvas.clientWidth || canvas.height !== canvas.clientHeight) {
      canvas.width = canvas.clientWidth;
      canvas.height = canvas.clientHeight;
    }

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Atualiza limites com base no traçado ou nos carros
    const pointsToBound = (trackShape && trackShape.length > 5) ? trackShape : cars;
    pointsToBound.forEach(p => {
      const px = p.x || (Array.isArray(p) ? p[0] : 0);
      const pz = p.z || (Array.isArray(p) ? p[1] : 0);
      if (px !== 0 || pz !== 0) {
        trackBounds.minX = Math.min(trackBounds.minX, px);
        trackBounds.maxX = Math.max(trackBounds.maxX, px);
        trackBounds.minZ = Math.min(trackBounds.minZ, pz);
        trackBounds.maxZ = Math.max(trackBounds.maxZ, pz);
      }
    });

    const rangeX = (trackBounds.maxX - trackBounds.minX) || 1;
    const rangeZ = (trackBounds.maxZ - trackBounds.minZ) || 1;
    const pad = 28;
    const w = canvas.width - (pad * 2);
    const h = canvas.height - (pad * 2);

    // Mantém proporção da pista (aspect ratio real sem distorcer)
    const scale = Math.min(w / rangeX, h / rangeZ);
    const offsetX = pad + (w - (rangeX * scale)) / 2;
    const offsetZ = pad + (h - (rangeZ * scale)) / 2;

    const toCanvasX = (x) => offsetX + (x - trackBounds.minX) * scale;
    const toCanvasY = (z) => offsetZ + (z - trackBounds.minZ) * scale;

    // 1. DESENHA A PISTA ASFALTADA (LINHA CONTÍNUA DO CIRCUITO)
    if (trackShape && trackShape.length > 5) {
      // Asfalto escuro de base
      ctx.beginPath();
      ctx.strokeStyle = '#272e42';
      ctx.lineWidth = 14;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      trackShape.forEach((p, idx) => {
        const cx = toCanvasX(p[0]);
        const cy = toCanvasY(p[1]);
        if (idx === 0) ctx.moveTo(cx, cy);
        else ctx.lineTo(cx, cy);
      });
      ctx.closePath();
      ctx.stroke();

      // Guia central da pista (traçado de corrida)
      ctx.beginPath();
      ctx.strokeStyle = '#475569';
      ctx.lineWidth = 2;
      trackShape.forEach((p, idx) => {
        const cx = toCanvasX(p[0]);
        const cy = toCanvasY(p[1]);
        if (idx === 0) ctx.moveTo(cx, cy);
        else ctx.lineTo(cx, cy);
      });
      ctx.closePath();
      ctx.stroke();
    }

    // 2. DESENHA OS 22 CARROS COM O NÚMERO DE POSIÇÃO
    cars.forEach(c => {
      if (c.x === 0 && c.z === 0) return;
      const cx = toCanvasX(c.x);
      const cy = toCanvasY(c.z);

      if (c.is_player) {
        // Carro do Jogador (Destaque Verde Neon com Halo)
        ctx.beginPath();
        ctx.arc(cx, cy, 11, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 255, 85, 0.35)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(cx, cy, 8, 0, Math.PI * 2);
        ctx.fillStyle = '#00ff55';
        ctx.fill();
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.font = 'bold 9px sans-serif';
        ctx.fillStyle = '#000';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(c.pos, cx, cy);
      } else {
        // Carros Adversários (Todos na Mesma Cor Azul Celeste com Número da Posição em Preto)
        ctx.beginPath();
        ctx.arc(cx, cy, 7, 0, Math.PI * 2);
        ctx.fillStyle = '#38bdf8';
        ctx.fill();
        ctx.strokeStyle = '#075985';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.font = 'bold 8.5px sans-serif';
        ctx.fillStyle = '#000000';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(c.pos, cx, cy);
      }
    });
  }

  // LOOP TELEMETRIA
    let manualModoSTest = false;
  function toggleModoSTest() {
    manualModoSTest = !manualModoSTest;
    const drsBox = document.getElementById('drsBox');
    const drsStatus = document.getElementById('drsStatus');
    if (manualModoSTest) {
      drsBox.className = 'drs-vertical-box on-active';
      drsStatus.textContent = 'ON';
    } else {
      drsBox.className = 'drs-vertical-box off';
      drsStatus.textContent = 'OFF';
    }
  }

  // =========================================
  // SCANNER DIAGNÓSTICO DE SAÍDAS UDP
  // =========================================
  const scannerModal = document.getElementById('scannerModal');
  let isScannerOpen = false;

  function openScanner() {
    isScannerOpen = true;
    scannerModal.classList.add('active');
  }
  function closeScanner() {
    isScannerOpen = false;
    scannerModal.classList.remove('active');
  }

  // Cria os 24 botões luminosos na grade
  const scanChannels = [
    { id: "01", key: "CAN_01_P6_Clutch_B14", label: "P6 Clutch (B14)" },
    { id: "02", key: "CAN_02_P6_DRS_B18", label: "P6 DRS Flag (B18)" },
    { id: "03", key: "CAN_03_P6_RevBit_B20", label: "P6 RevBit (B20)" },
    { id: "04", key: "CAN_04_P6_RevBit_B21", label: "P6 RevBit (B21)" },
    { id: "05", key: "CAN_05_P6_EngineTemp_B38", label: "P6 EngTemp (B38)" },
    { id: "06", key: "CAN_06_P6_SurfaceType_B56", label: "P6 SurfType (B56)" },
    { id: "07", key: "CAN_07_P6_Tail_ByteMinus5", label: "P6 Tail (-5)" },
    { id: "08", key: "CAN_08_P6_Tail_ByteMinus4", label: "P6 Tail (-4)" },
    { id: "09", key: "CAN_09_P6_Tail_ByteMinus3", label: "P6 Tail (-3)" },
    { id: "10", key: "CAN_10_P6_Tail_ByteMinus2", label: "P6 Tail (-2)" },
    { id: "11", key: "CAN_11_P7_TC_B0", label: "P7 TC (B0)" },
    { id: "12", key: "CAN_12_P7_ABS_B1", label: "P7 ABS (B1)" },
    { id: "13", key: "CAN_13_P7_FuelMix_B2", label: "P7 FuelMix (B2)" },
    { id: "14", key: "CAN_14_P7_MaxGears_B21", label: "P7 MaxGears (B21)" },
    { id: "15", key: "CAN_15_P7_DRS_Allowed_B22", label: "P7 DRS Allowed (B22)" },
    { id: "16", key: "CAN_16_P7_DRS_Dist_B23_24", label: "P7 DRS Dist (B23-24)" },
    { id: "17", key: "CAN_17_P7_DRS_Disabled_B25", label: "P7 DRS Dis (B25)" },
    { id: "18", key: "CAN_18_P7_ActualTyre_B26", label: "P7 Tyre (B26)" },
    { id: "19", key: "CAN_19_P7_NetworkPaused_B55", label: "P7 NetPause (B55)" },
    { id: "20", key: "CAN_20_P7_Extra_B56", label: "P7 Extra (B56)" },
    { id: "21", key: "CAN_21_P7_Extra_B57", label: "P7 Extra (B57)" },
    { id: "22", key: "CAN_22_P7_Extra_B58", label: "P7 Extra (B58)" },
    { id: "23", key: "CAN_23_P10_DRS_Fault_B30", label: "P10 DRS Fault (B30)" },
    { id: "24", key: "CAN_24_P10_ERS_Fault_B31", label: "P10 ERS Fault (B31)" },
  ];

  // Modo lista em tela cheia (botões removidos para exibição máxima de linhas)

  async function clearSnifferLog() {
    try {
      await fetch('/clear_sniffer');
    } catch(e) {}
    document.getElementById('snifferLogList').innerHTML = '<div style="color:#64748b; font-style:italic;">Registro limpo com sucesso! Aguardando acionamento do Modo S...</div>';
  }

async function syncTelemetry() {
    try {
      const res = await fetch('/telemetry');
      if (res.ok) {
        const d = await res.json();

        document.getElementById('ipValue').textContent = d.local_ip || '127.0.0.1';

        serverInPit = d.in_pit;
        if (!isHoldingRight) {
          if (serverInPit) {
            gScreen.classList.add('active');
          } else {
            gScreen.classList.remove('active');
          }
        }

        if (gScreen.classList.contains('active')) {
          drawTrackAndCars(d.track_shape, d.cars_gps);
          const tbody = document.getElementById('lbBody');
          tbody.innerHTML = '';
          document.getElementById('lbTotalCars').textContent = d.total_cars + ' Carros';

          (d.leaderboard || []).forEach(row => {
            const tr = document.createElement('tr');
            tr.className = 'lb-row ' + (row.is_player ? 'player-row' : '');
            tr.innerHTML = `
              <td class="col-pos" style="font-weight:900;">${row.pos}</td>
              <td class="col-driver" style="color:${row.color}; font-weight:900;">${row.name}</td>
              <td class="col-tyre"><span class="tyre-chip" style="background:${row.tyre_color};">${row.tyre}</span></td>
              <td class="col-time" style="font-variant-numeric:tabular-nums;">${row.best_lap}</td>
              <td class="col-gap" style="font-variant-numeric:tabular-nums; color:${row.gap === 'LÍDER' ? '#22c55e' : '#cbd5e1'};">${row.gap}</td>
            `;
            tbody.appendChild(tr);
          });
        }

        // BANDEIRAS
        if (d.flag !== lastFlag) {
          if (d.flag === 3) triggerFlashAlert('⚠️', 'BANDEIRA AMARELA', 'PERIGO NO SETOR - REDUZA A VELOCIDADE', '#eab308', '#000');
          else if (d.flag === 4) triggerFlashAlert('🚩', 'BANDEIRA VERMELHA', 'SESSÃO SUSPENSA - RETORNE AOS BOXES', '#dc2626', '#fff');
          else if (d.flag === 1 && lastFlag !== 0) triggerFlashAlert('🟢', 'BANDEIRA VERDE', 'PISTA LIBERADA', '#16a34a', '#fff');
          lastFlag = d.flag;
        }

        if (d.safety_car !== lastSC) {
          if (d.safety_car === 1) triggerFlashAlert('🚨', 'SAFETY CAR EM PISTA', 'MANTENHA O DELTA POSITIVO', '#ca8a04', '#000');
          else if (d.safety_car === 2) triggerFlashAlert('⚡', 'VIRTUAL SAFETY CAR', 'MANTENHA O DELTA POSITIVO', '#ea580c', '#fff');
          lastSC = d.safety_car;
        }

                if (isScannerOpen) {
          // Atualiza lista de logs em tempo real
          const logBox = document.getElementById('snifferLogList');
          if (d.sniffer_log && d.sniffer_log.length > 0) {
            logBox.innerHTML = d.sniffer_log.map(e => `<div class="sniffer-log-entry">${e}</div>`).join('');
          }


        }

        // COCKPIT
        document.getElementById('speed').textContent = d.speed;
        document.getElementById('gear').textContent = d.gear === 0 ? 'N' : d.gear === -1 ? 'R' : d.gear;

        const sugg = d.suggested_gear;
        document.getElementById('suggGear').textContent = (sugg > 0 && sugg <= 8) ? ('PRÓXIMA: ' + sugg) : 'PRÓXIMA: -';

        const pct = d.rev_lights_pct || 0;
        const activeCount = Math.floor((pct / 100) * 15);
        for (let i = 0; i < 15; i++) {
          const l = document.getElementById('led_' + i);
          if (i < activeCount) l.classList.add('on');
          else l.classList.remove('on');
        }

        const t = d.tyres;
        const setTyre = (tempId, wearId, temp, wear) => {
          const el = document.getElementById(tempId);
          el.textContent = temp + '°C';
          el.style.color = getTempHex(temp);
          document.getElementById(wearId).textContent = wear + '%';
        };
        setTyre('flTemp', 'flWear', t.fl_temp, t.fl_wear);
        setTyre('frTemp', 'frWear', t.fr_temp, t.fr_wear);
        setTyre('rlTemp', 'rlWear', t.rl_temp, t.rl_wear);
        setTyre('rrTemp', 'rrWear', t.rr_temp, t.rr_wear);

        const compColor = t.compound_color || '#eab308';
        document.getElementById('tyreRingL').setAttribute('stroke', compColor);
        document.getElementById('tyreRingR').setAttribute('stroke', compColor);

        updateWing('flWingDot', 'flWingText', 'ASA ESQ', d.wing_damage.fl);
        updateWing('frWingDot', 'frWingText', 'ASA DIR', d.wing_damage.fr);

        if (!manualModoSTest) {
          const drsBox = document.getElementById('drsBox');
          const drsStatus = document.getElementById('drsStatus');
          if (d.drs === 1 || d.drs > 0) {
            drsBox.className = 'drs-vertical-box on-active';
            drsStatus.textContent = 'ON';
          } else if (d.drs_allowed === 1 || d.drs_allowed > 0) {
            drsBox.className = 'drs-vertical-box avail';
            drsStatus.textContent = 'AVAIL';
          } else {
            drsBox.className = 'drs-vertical-box off';
            drsStatus.textContent = 'OFF';
          }
        }

        document.getElementById('ersVal').textContent = Math.round(d.ers_pct) + '%';
        document.getElementById('ersMode').textContent = d.ers_mode;
        const fDelta = d.fuel_delta >= 0 ? '+' + d.fuel_delta.toFixed(2) : d.fuel_delta.toFixed(2);
        document.getElementById('fuelVal').textContent = fDelta;

        document.getElementById('rain5').textContent = d.weather.rain_5m + '%';
        document.getElementById('rain10').textContent = d.weather.rain_10m + '%';
        document.getElementById('pitRejoin').textContent = 'P' + d.pit_rejoin_pos;

        document.getElementById('pos').textContent = 'P' + d.position + '/' + d.total_cars;
        document.getElementById('lap').textContent = 'Volta ' + d.lap_num + '/' + d.total_laps;

        const scBanner = document.getElementById('scBanner');
        const normalBlocks = document.querySelectorAll('.normal-time-block');
        if (d.safety_car === 1 || d.safety_car === 2) {
          normalBlocks.forEach(b => b.style.display = 'none');
          scBanner.classList.add('active');
          if (d.safety_car === 2) {
            scBanner.classList.add('vsc-pulse-anim');
            document.getElementById('scTitle').textContent = 'VIRTUAL SAFETY CAR';
          } else {
            scBanner.classList.remove('vsc-pulse-anim');
            document.getElementById('scTitle').textContent = 'SAFETY CAR';
          }
          const scDeltaEl = document.getElementById('scDelta');
          const scD = d.sc_delta;
          scDeltaEl.textContent = (scD >= 0 ? '+' : '') + scD.toFixed(3) + 's';
          scDeltaEl.className = 'sc-delta-val ' + (scD >= 0 ? 'safe' : 'danger');
        } else {
          normalBlocks.forEach(b => b.style.display = 'flex');
          scBanner.classList.remove('active');
          document.getElementById('lapTime').textContent = d.lap_time;
          document.getElementById('lastLap').textContent = d.last_lap;
          const deltaEl = document.getElementById('deltaVal');
          deltaEl.textContent = (d.delta >= 0 ? '+' : '') + d.delta.toFixed(3) + 's';
          deltaEl.style.color = d.delta <= 0 ? '#00ff55' : '#ef4444';
        }
      }
    } catch (e) {}
    setTimeout(syncTelemetry, 40);
  }

  syncTelemetry();
</script>
</body>
</html>
"""

# ==========================================
# SERVIDOR HTTP LOCAL
# ==========================================
class DashboardServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode('utf-8'))
        elif self.path == '/telemetry':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(telemetry).encode('utf-8'))
        elif self.path == '/clear_sniffer':
            sniffer_recent_changes.clear()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'{"status":"cleared"}')
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass

def run_http_server():
    server = HTTPServer(('0.0.0.0', 5000), DashboardServer)
    print("=" * 60)
    print(f">> SERVIDOR F1 25 COMPLETO ATIVO [{APP_VERSION}] (COM MAPA DA PISTA)!")
    print(f">> SEU IP PARA O XBOX: {LOCAL_IP}")
    print(f">> Abra no navegador do aparelho em: http://localhost:5000")
    print(">> Aguardando conexao UDP do Xbox na porta 20777...")
    print("=" * 60)
    server.serve_forever()

# ==========================================
# RECEPTOR E DECODIFICADOR UDP DO F1 25
# ==========================================
def format_time_ms(ms):
    if ms == 0: return "0:00.000"
    m = ms // 60000
    s = (ms % 60000) // 1000
    millis = ms % 1000
    return f"{m}:{s:02d}.{millis:03d}"

def udp_telemetry_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 20777))

    frame_counter = 0

    while True:
        try:
            data, _ = sock.recvfrom(2048)
            data_len = len(data)
            if data_len < 29:
                continue

            header = struct.unpack_from('<HBBBBBQfIIBB', data, 0)
            packet_format = header[0]
            game_year = header[1]
            packet_id = header[5]
            session_uid = header[6]
            session_time = header[7]
            player_idx = header[10]

            telemetry["connected"] = True

            # DETECÇÃO AUTOMÁTICA DE REINÍCIO OU NOVA SESSÃO:
            # Se o UID da sessão mudar OU o tempo da sessão retroceder para o início (< 4s após ter passado de 10s)
            if session_tracker["uid"] == 0:
                session_tracker["uid"] = session_uid
                session_tracker["last_time"] = session_time
            elif session_uid != session_tracker["uid"] or (session_time < 4.0 and session_tracker["last_time"] > 10.0):
                session_tracker["uid"] = session_uid
                session_tracker["last_time"] = session_time
                reset_session_data()
            else:
                session_tracker["last_time"] = max(session_tracker["last_time"], session_time)

            # Identifica número de carros (Season Pack 2026 possui até 24 carros)
            is_2026_pack = (packet_format >= 2026 or game_year >= 26 or data_len in (1399, 1470, 1445, 1133, 1448, 1325, 1478))
            num_cars_total = telemetry.get("total_cars", 22)
            if num_cars_total < 20 or num_cars_total > 24:
                num_cars_total = 24 if is_2026_pack else 22

            # ------------------------------------------
            # PACKET 0: MOTION (COORDENADAS GPS E TRAÇADO)
            # ------------------------------------------
            if packet_id == 0:
                frame_counter += 1
                gps_list = []
                t_len = telemetry["track_length"]
                motion_stride = 60
                max_motion_cars = min(24, (data_len - 29) // motion_stride)

                for i in range(max_motion_cars):
                    offset = 29 + (i * motion_stride)
                    if offset + 12 <= data_len:
                        x, _, z = struct.unpack_from('<fff', data, offset)
                        cars_info[i]["x"] = x
                        cars_info[i]["z"] = z
                        gps_list.append({
                            "x": x,
                            "z": z,
                            "pos": cars_info[i]["pos"],
                            "is_player": (i == player_idx),
                            "color": cars_info[i]["color"]
                        })

                        ldist = cars_info[i]["lap_dist"]
                        if t_len > 100 and 0 < ldist < t_len:
                            b_idx = int((ldist / t_len) * 100) % 100
                            track_bins[b_idx] = (round(x, 1), round(z, 1))

                telemetry["cars_gps"] = gps_list

                if frame_counter % 10 == 0:
                    shape = get_interpolated_track()
                    if len(shape) > 10:
                        telemetry["track_shape"] = shape

            # ------------------------------------------
            # PACKET 1: SESSÃO
            # ------------------------------------------
            elif packet_id == 1 and data_len >= 156:
                telemetry["total_laps"] = data[32]
                telemetry["track_length"] = struct.unpack_from('<H', data, 33)[0] or 5000
                telemetry["safety_car"] = data[153]
                num_weather = data[155]
                offset = 156
                rain_5m = 0
                rain_10m = 0
                for _ in range(min(num_weather, 20)):
                    if offset + 8 <= data_len:
                        w_sample = struct.unpack_from('<BBBbbbbB', data, offset)
                        time_offset = w_sample[1]
                        rain_pct = w_sample[7]
                        if time_offset == 5: rain_5m = rain_pct
                        elif time_offset == 10: rain_10m = rain_pct
                        offset += 8
                telemetry["weather"]["rain_5m"] = rain_5m
                telemetry["weather"]["rain_10m"] = rain_10m

                # Detecta bandeira amarela geral na pista caso zonas de fiscais reportem perigo
                num_marshal_zones = data[35] if data_len >= 36 else 0
                if num_marshal_zones > 0:
                    m_offset = 36
                    has_yellow = False
                    for _ in range(min(num_marshal_zones, 21)):
                        if m_offset + 5 <= data_len:
                            m_flag = struct.unpack_from('<b', data, m_offset + 4)[0]
                            if m_flag == 3:
                                has_yellow = True
                                break
                            m_offset += 5
                    if has_yellow and telemetry["flag"] == 0:
                        telemetry["flag"] = 3

            # ------------------------------------------
            # PACKET 2: LAP DATA (57 BYTES POR CARRO)
            # ------------------------------------------
            elif packet_id == 2:
                car_lap_size = 57
                lap_fmt = '<IIHBHBHBHBfff15BHHBfB'
                leaderboard_rows = []
                max_lap_cars = min(24, (data_len - 29) // car_lap_size)

                # Desempacota dados do jogador DIRETAMENTE pelo player_idx
                p_lap_offset = 29 + (player_idx * car_lap_size)
                if p_lap_offset + car_lap_size <= data_len:
                    p_lap = struct.unpack_from(lap_fmt, data, p_lap_offset)
                    p_last_lap_ms = p_lap[0]
                    p_curr_lap_ms = p_lap[1]
                    p_gap_leader_ms = p_lap[8] + (p_lap[9] * 60000)
                    p_sc_delta = p_lap[12]
                    p_pos = p_lap[13]
                    p_lap_num = p_lap[14]
                    p_pit_status = p_lap[15]
                    p_driver_status = p_lap[25]
                    p_pit_lane_timer = p_lap[27]

                    # Na volta 1 de uma sessão recém-iniciada, a última volta não pertence a esta sessão
                    if p_lap_num <= 1:
                        telemetry["last_lap"] = "0:00.000"
                    else:
                        telemetry["last_lap"] = format_time_ms(p_last_lap_ms)
                    telemetry["lap_time"] = format_time_ms(p_curr_lap_ms)
                    telemetry["sc_delta"] = p_sc_delta
                    telemetry["position"] = p_pos if p_pos > 0 else 1
                    telemetry["lap_num"] = p_lap_num if p_lap_num > 0 else 1

                    # CÁLCULO DE DELTA EM TEMPO REAL (DINÂMICO AO LONGO DE TODA A VOLTA)
                    p_lap_dist = p_lap[10] # Distância percorrida na volta em metros

                    # Detecta início de uma nova volta para atualizar a linha de referência
                    if p_lap_num != live_delta_tracker["current_lap_num"]:
                        if p_last_lap_ms >= 30000 and len(live_delta_tracker["current_timeline"]) > 20:
                            # Se a volta recém-concluída foi melhor, ou se ainda não tínhamos referência, adota como referência
                            if (player_pace["best_ms"] == 0 or p_last_lap_ms <= player_pace["best_ms"]):
                                player_pace["best_ms"] = p_last_lap_ms
                                live_delta_tracker["ref_timeline"] = dict(live_delta_tracker["current_timeline"])
                            elif not live_delta_tracker["ref_timeline"]:
                                live_delta_tracker["ref_timeline"] = dict(live_delta_tracker["current_timeline"])
                        live_delta_tracker["current_timeline"].clear()
                        live_delta_tracker["current_lap_num"] = p_lap_num

                    # Durante a volta, amostra a cada 10 metros e compara com a volta de referência em tempo real
                    if p_curr_lap_ms > 0 and p_lap_dist > 5.0:
                        dist_bin = int(p_lap_dist / 10.0)
                        live_delta_tracker["current_timeline"][dist_bin] = p_curr_lap_ms

                        # Se temos uma volta de referência registrada, compara instantaneamente
                        if live_delta_tracker["ref_timeline"]:
                            ref_time = live_delta_tracker["ref_timeline"].get(dist_bin)
                            if ref_time is None:
                                # Busca bin adjacente mais próximo
                                for offset_b in (-1, 1, -2, 2):
                                    if (dist_bin + offset_b) in live_delta_tracker["ref_timeline"]:
                                        ref_time = live_delta_tracker["ref_timeline"][dist_bin + offset_b]
                                        break
                            if ref_time is not None and ref_time > 0:
                                diff_s = (p_curr_lap_ms - ref_time) / 1000.0
                                live_delta_tracker["last_delta_val"] = round(diff_s, 3)

                    telemetry["delta"] = live_delta_tracker["last_delta_val"]

                    # Entrada automática no modo box: parado na garagem (0), entrando/no box (1, 2) ou timer ativo
                    if p_pit_status in (1, 2) or p_driver_status == 0 or p_pit_lane_timer == 1:
                        telemetry["in_pit"] = True
                    elif p_pit_status == 0 and p_driver_status in (1, 3, 4):
                        telemetry["in_pit"] = False

                    telemetry["pit_rejoin_pos"] = min(telemetry["total_cars"], p_pos + 3)

                # Processa todos os carros para a tabela de classificação
                # Registra os melhores tempos APENAS quando o carro completar voltas válidas na pista (mínimo 30 segundos)
                for i in range(max_lap_cars):
                    c_offset = 29 + (i * car_lap_size)
                    if c_offset + car_lap_size <= data_len:
                        lap_unpacked = struct.unpack_from(lap_fmt, data, c_offset)
                        last_lap_ms = lap_unpacked[0]
                        curr_lap_ms = lap_unpacked[1]
                        lap_distance = lap_unpacked[10]
                        pos = lap_unpacked[13]
                        c_lap_num = lap_unpacked[14]
                        c_driver_status = lap_unpacked[25]

                        cars_info[i]["pos"] = pos
                        cars_info[i]["lap_dist"] = lap_distance

                        # Se a sessão foi reiniciada e o carro está na volta 1, não tem volta concluída nesta sessão
                        if c_lap_num <= 1:
                            cars_info[i]["best_lap_ms"] = 0
                        elif last_lap_ms >= 30000 and c_lap_num > 1:
                            if cars_info[i]["best_lap_ms"] == 0 or last_lap_ms < cars_info[i]["best_lap_ms"]:
                                cars_info[i]["best_lap_ms"] = last_lap_ms

                # Encontra a melhor volta geral da sessão entre todos os pilotos
                valid_bests = [cars_info[i]["best_lap_ms"] for i in range(max_lap_cars) if cars_info[i]["best_lap_ms"] > 0]
                session_best_ms = min(valid_bests) if valid_bests else 0

                for i in range(max_lap_cars):
                    pos = cars_info[i]["pos"]
                    if 0 < pos <= telemetry["total_cars"]:
                        b_ms = cars_info[i]["best_lap_ms"]
                        if b_ms > 0:
                            best_time_str = format_time_ms(b_ms)
                            if session_best_ms > 0:
                                diff_ms = b_ms - session_best_ms
                                best_gap_str = "LÍDER" if diff_ms <= 0 else f"+{(diff_ms / 1000.0):.3f}s"
                            else:
                                best_gap_str = "LÍDER" if pos == 1 else "+0.000s"
                        else:
                            best_time_str = "-:--.---"
                            best_gap_str = "-"

                        leaderboard_rows.append({
                            "pos": f"P{pos}",
                            "num_pos": pos,
                            "name": cars_info[i]["name"],
                            "team": cars_info[i]["team"],
                            "color": cars_info[i]["color"],
                            "tyre": cars_info[i]["compound"],
                            "tyre_color": cars_info[i]["compound_color"],
                            "best_lap": best_time_str,
                            "gap": best_gap_str,
                            "is_player": (i == player_idx)
                        })

                leaderboard_rows.sort(key=lambda r: r["num_pos"])
                telemetry["leaderboard"] = leaderboard_rows

            # ------------------------------------------
            # PACKET 4: PARTICIPANTES
            # ------------------------------------------
                        # ------------------------------------------
            # PACKET 3: EVENTOS (ACIONAMENTO DE BOTÕES, DRSE, DRSD, OVTK)
            # ------------------------------------------
            elif packet_id == 3 and data_len >= 33:
                event_code = data[29:33].decode('latin-1', errors='ignore')
                telemetry["last_event"] = event_code
                ev_time_str = time.strftime('%H:%M:%S')

                extra_detail = ""
                if event_code == 'BUTN' and data_len >= 37:
                    btn_val = struct.unpack_from('<I', data, 33)[0]
                    btn_names = []
                    if btn_val & 0x0001: btn_names.append("A / Cruz")
                    if btn_val & 0x0002: btn_names.append("Y / Triângulo")
                    if btn_val & 0x0004: btn_names.append("B / Círculo")
                    if btn_val & 0x0008: btn_names.append("X / Quadrado")
                    if btn_val & 0x0010: btn_names.append("D-Pad Esq")
                    if btn_val & 0x0020: btn_names.append("D-Pad Dir")
                    if btn_val & 0x0040: btn_names.append("D-Pad Cima")
                    if btn_val & 0x0080: btn_names.append("D-Pad Baixo")
                    if btn_val & 0x0100: btn_names.append("Pause / Opções")
                    if btn_val & 0x0200: btn_names.append("LB / L1")
                    if btn_val & 0x0400: btn_names.append("RB / R1")
                    if btn_val & 0x0800: btn_names.append("LT / L2")
                    if btn_val & 0x1000: btn_names.append("RT / R2")
                    if btn_val & 0x2000: btn_names.append("Analógico Esq Click")
                    if btn_val & 0x4000: btn_names.append("Analógico Dir Click")
                    if btn_val & 0x00080000: btn_names.append("Ação Especial / DRS")
                    btn_str = " + ".join(btn_names) if btn_names else f"Código 0x{btn_val:08X}"
                    extra_detail = f"[{btn_str}]"
                elif event_code in ('DRSE', 'DRSD', 'OVTK'):
                    extra_detail = f"Status: {event_code}"

                log_entry = f"[{ev_time_str}] Pacote 3 EVENTO: {event_code} {extra_detail}"
                sniffer_recent_changes.insert(0, log_entry)
                if len(sniffer_recent_changes) > 250:
                    sniffer_recent_changes.pop()

            elif packet_id == 4 and data_len >= 30:
                num_cars = data[29]
                if 20 <= num_cars <= 24:
                    telemetry["total_cars"] = num_cars

                body_len = data_len - 30
                p_size = 60 if is_2026_pack else (body_len // num_cars if num_cars > 0 else 60)

                for i in range(min(num_cars, 24)):
                    p_offset = 30 + (i * p_size)
                    if p_offset + 32 <= data_len:
                        clean_name = ""
                        # Extrai o nome de texto (offset 7 oficial do F1: char m_name[48])
                        for name_off in (7, 8, 10, 9, 6):
                            if p_offset + name_off + 8 <= data_len:
                                raw_n = data[p_offset + name_off : p_offset + name_off + 48]
                                parts = raw_n.split(b'\x00')
                                cand = parts[0].decode('utf-8', errors='ignore').strip()
                                if len(cand) >= 2 and any(c.isalpha() for c in cand):
                                    clean_name = cand
                                    break

                        driver_id_16 = struct.unpack_from('<H', data, p_offset + 1)[0]
                        team_id_16 = struct.unpack_from('<H', data, p_offset + 5)[0] if p_offset + 7 <= data_len else 255
                        driver_id_8 = data[p_offset + 1]
                        team_id_8 = data[p_offset + 3] if p_offset + 4 <= data_len else 255

                        driver_id = driver_id_16 if driver_id_16 in DRIVERS else driver_id_8
                        team_id = team_id_16 if team_id_16 in TEAMS else team_id_8

                        if not clean_name:
                            clean_name = DRIVERS.get(driver_id, f"Piloto {i+1}")

                        clean_upper = clean_name.upper()
                        # Resolve Escuderia e Cor Oficial da Temporada 2026
                        found_team = None
                        found_color = None
                        for d_key, (t_n, t_c) in DRIVER_TEAMS_2026.items():
                            if d_key in clean_upper:
                                found_team = t_n
                                found_color = t_c
                                break

                        if not found_team:
                            found_team, found_color = TEAMS.get(team_id, ("F1 Team", "#38bdf8"))

                        cars_info[i]["name"] = clean_name
                        cars_info[i]["team"] = found_team
                        cars_info[i]["color"] = found_color

            # ------------------------------------------
            # PACKET 6: TELEMETRIA DO CARRO
            # ------------------------------------------
            elif packet_id == 6:
                car_tel_stride = 60
                car_tel_offset = 29 + (player_idx * car_tel_stride)
                if car_tel_offset + car_tel_stride <= data_len:
                    car_tel = struct.unpack_from('<HfffBbHBBH4H4B4BH4f4B', data, car_tel_offset)
                    telemetry["speed"] = car_tel[0]
                    telemetry["gear"] = car_tel[5]
                    telemetry["rpm"] = car_tel[6]
                    # MODO S (DRS / Aerodinâmica Ativa 2026):
                    # 1. Leitura direta do byte oficial m_drs no Packet 6 (offset 18) e bytes adjacentes
                    speed_kmh = car_tel[0]
                    throttle_val = car_tel[1]
                    brake_val = car_tel[3]
                    gear_val = car_tel[5]

                    raw_drs_byte = data[car_tel_offset + 18] if car_tel_offset + 18 < data_len else 0
                    drs_active = 1 if (car_tel[7] > 0 or raw_drs_byte == 1) else 0

                    if not drs_active and car_tel_offset + 22 <= data_len:
                        if any(data[car_tel_offset + off] == 1 for off in (17, 19, 20)):
                            drs_active = 1

                    telemetry["drs"] = drs_active
                    telemetry["rev_lights_pct"] = car_tel[8]
                    # TEMPERATURA EXTERNA / SUPERFÍCIE (Surface Temperature - car_tel[14..17])
                    telemetry["tyres"]["rl_temp"] = car_tel[14]
                    telemetry["tyres"]["rr_temp"] = car_tel[15]
                    telemetry["tyres"]["fl_temp"] = car_tel[16]
                    telemetry["tyres"]["fr_temp"] = car_tel[17]

                # Marcha sugerida da próxima curva:
                # 1. Tenta pelo tail_offset clássico (29 + 22*60 + 2 = offset 1351)
                sugg_found = 0
                tail_off_22 = 29 + (22 * 60)
                if tail_off_22 + 3 <= data_len:
                    val_22 = struct.unpack_from('<b', data, tail_off_22 + 2)[0]
                    if 1 <= val_22 <= 8:
                        sugg_found = val_22

                if not sugg_found:
                    tail_off_24 = 29 + (24 * 60)
                    if tail_off_24 + 3 <= data_len:
                        val_24 = struct.unpack_from('<b', data, tail_off_24 + 2)[0]
                        if 1 <= val_24 <= 8:
                            sugg_found = val_24

                if not sugg_found:
                    raw_last = struct.unpack_from('<b', data, data_len - 1)[0]
                    if 1 <= raw_last <= 8:
                        sugg_found = raw_last

                telemetry["suggested_gear"] = sugg_found
                # Varredura completa de todos os 60 bytes do carro do jogador no Pacote 6
                if car_tel_offset + car_tel_stride <= data_len:
                    current_p6_slice = data[car_tel_offset : car_tel_offset + car_tel_stride]
                    for b_i in range(len(current_p6_slice)):
                        active_changed_bytes["p6"][f"B{b_i}"] = current_p6_slice[b_i]

                    if raw_prev_buffers["p6"] is not None and len(raw_prev_buffers["p6"]) == len(current_p6_slice):
                        for b_i in range(len(current_p6_slice)):
                            # Filtra rigorosamente canais analógicos contínuos para manter o log 100% limpo focado no MODO S
                            # Ignora: Velocidade (0..1), Pedais/Volante (2..13), RPM (16..17), LEDs (19), Freios (22..29), Temperaturas (30..39), Pressões (40..55)
                            if (0 <= b_i <= 13) or (16 <= b_i <= 17) or (b_i == 19) or (22 <= b_i <= 55):
                                continue
                            if current_p6_slice[b_i] != raw_prev_buffers["p6"][b_i]:
                                t_str = time.strftime('%H:%M:%S')
                                entry = f"[{t_str}] Pacote 6 Byte {b_i}: {raw_prev_buffers['p6'][b_i]} -> {current_p6_slice[b_i]}"
                                sniffer_recent_changes.insert(0, entry)
                                if len(sniffer_recent_changes) > 250:
                                    sniffer_recent_changes.pop()

                    raw_prev_buffers["p6"] = current_p6_slice

                # Atualiza canais do Scanner Diagnóstico do Pacote 6
                if car_tel_offset + car_tel_stride <= data_len:
                    udp_scanner["CAN_01_P6_Clutch_B14"] = data[car_tel_offset + 14]
                    udp_scanner["CAN_02_P6_DRS_B18"] = data[car_tel_offset + 18]
                    udp_scanner["CAN_03_P6_RevBit_B20"] = data[car_tel_offset + 20]
                    udp_scanner["CAN_04_P6_RevBit_B21"] = data[car_tel_offset + 21]
                    udp_scanner["CAN_05_P6_EngineTemp_B38"] = data[car_tel_offset + 38]
                    udp_scanner["CAN_06_P6_SurfaceType_B56"] = data[car_tel_offset + 56]

                if data_len >= 5:
                    udp_scanner["CAN_07_P6_Tail_ByteMinus5"] = data[data_len - 5]
                    udp_scanner["CAN_08_P6_Tail_ByteMinus4"] = data[data_len - 4]
                    udp_scanner["CAN_09_P6_Tail_ByteMinus3"] = data[data_len - 3]
                    udp_scanner["CAN_10_P6_Tail_ByteMinus2"] = data[data_len - 2]


            # ------------------------------------------
            # PACKET 7: CAR STATUS (COMBUSTÍVEL, ERS E DRS)
            # ------------------------------------------
            elif packet_id == 7:
                car_status_size = 59 if is_2026_pack or data_len >= 29 + (22 * 59) else 55
                comp_off = 27 if car_status_size >= 58 else 26
                age_off = 28 if car_status_size >= 58 else 27
                flag_off = 29 if car_status_size >= 58 else 28
                ers_off = 38 if car_status_size >= 58 else 37
                mode_off = 42 if car_status_size >= 58 else 41

                # 1. Atualiza dados do JOGADOR DIRETAMENTE pelo player_idx
                p_status_offset = 29 + (player_idx * car_status_size)
                if p_status_offset + 44 <= data_len:
                    # Pit Limiter ativo coloca automaticamente no Modo Box
                    pit_limiter = data[p_status_offset + 4]
                    if pit_limiter == 1:
                        telemetry["in_pit"] = True

                    # Combustível restante em voltas
                    f_delta = struct.unpack_from('<f', data, p_status_offset + 13)[0]
                    if -100.0 < f_delta < 100.0:
                        telemetry["fuel_delta"] = round(f_delta, 2)

                    # MODO S (DRS) autorização pela FIA na reta
                    raw_drs_allowed = data[p_status_offset + 22] if p_status_offset + 22 < data_len else 0
                    drs_dist = struct.unpack_from('<H', data, p_status_offset + 23)[0] if p_status_offset + 25 <= data_len else 65535
                    # Permitido quando o flag for 1 ou quando a distância até a zona for 0 em reta
                    if raw_drs_allowed == 1 or (0 < drs_dist < 20):
                        drs_allowed_val = 1
                    elif p_status_offset + 21 < data_len and data[p_status_offset + 21] == 1:
                        drs_allowed_val = 1
                    else:
                        drs_allowed_val = 0
                    telemetry["drs_allowed"] = drs_allowed_val
                    telemetry["tyres"]["age"] = data[p_status_offset + age_off]

                    # Bandeira do volante
                    car_flag = struct.unpack_from('<b', data, p_status_offset + flag_off)[0]
                    if car_flag in (0, 1, 2, 3, 4):
                        telemetry["flag"] = car_flag

                    # Composto visual do pneu do jogador
                    comp_id = data[p_status_offset + comp_off]
                    c_code, c_name, c_color = TYRE_MAP.get(comp_id, ("M", "MÉDIO", "#eab308"))
                    telemetry["tyres"]["compound"] = c_name
                    telemetry["tyres"]["compound_color"] = c_color

                    # ERS
                    if p_status_offset + mode_off < data_len:
                        ers_joules = struct.unpack_from('<f', data, p_status_offset + ers_off)[0]
                        mode_id = data[p_status_offset + mode_off]
                        if 0.0 <= ers_joules <= 5000000.0:
                            telemetry["ers_pct"] = min(100.0, max(0.0, (ers_joules / 4000000.0) * 100.0))
                        telemetry["ers_mode"] = ERS_MODES.get(mode_id, "MED")

                                # Atualiza canais do Scanner Diagnóstico do Pacote 7
                if p_status_offset + car_status_size <= data_len:
                    udp_scanner["CAN_11_P7_TC_B0"] = data[p_status_offset + 0]
                    udp_scanner["CAN_12_P7_ABS_B1"] = data[p_status_offset + 1]
                    udp_scanner["CAN_13_P7_FuelMix_B2"] = data[p_status_offset + 2]
                    udp_scanner["CAN_14_P7_MaxGears_B21"] = data[p_status_offset + 21]
                    udp_scanner["CAN_15_P7_DRS_Allowed_B22"] = data[p_status_offset + 22]
                    if p_status_offset + 25 <= data_len:
                        udp_scanner["CAN_16_P7_DRS_Dist_B23_24"] = struct.unpack_from('<H', data, p_status_offset + 23)[0]
                    if p_status_offset + 26 <= data_len:
                        udp_scanner["CAN_17_P7_DRS_Disabled_B25"] = data[p_status_offset + 25]
                        udp_scanner["CAN_18_P7_ActualTyre_B26"] = data[p_status_offset + 26]
                    if p_status_offset + 56 <= data_len:
                        udp_scanner["CAN_19_P7_NetworkPaused_B55"] = data[p_status_offset + 55]
                    if p_status_offset + 59 <= data_len:
                        udp_scanner["CAN_20_P7_Extra_B56"] = data[p_status_offset + 56]
                        udp_scanner["CAN_21_P7_Extra_B57"] = data[p_status_offset + 57]
                        udp_scanner["CAN_22_P7_Extra_B58"] = data[p_status_offset + 58]

                                # Varredura completa de todos os bytes do carro do jogador no Pacote 7
                if p_status_offset + car_status_size <= data_len:
                    current_p7_slice = data[p_status_offset : p_status_offset + car_status_size]
                    for b_i in range(len(current_p7_slice)):
                        active_changed_bytes["p7"][f"B{b_i}"] = current_p7_slice[b_i]

                    if raw_prev_buffers["p7"] is not None and len(raw_prev_buffers["p7"]) == len(current_p7_slice):
                        for b_i in range(len(current_p7_slice)):
                            # Filtra rigorosamente canais analógicos do Pacote 7 (combustível, RPM de motor, potências e Joules de ERS)
                            if (5 <= b_i <= 20) or (30 <= b_i <= 41) or (43 <= b_i <= 54):
                                continue
                            if current_p7_slice[b_i] != raw_prev_buffers["p7"][b_i]:
                                t_str = time.strftime('%H:%M:%S')
                                entry = f"[{t_str}] Pacote 7 Byte {b_i}: {raw_prev_buffers['p7'][b_i]} -> {current_p7_slice[b_i]}"
                                sniffer_recent_changes.insert(0, entry)
                                if len(sniffer_recent_changes) > 250:
                                    sniffer_recent_changes.pop()

                    raw_prev_buffers["p7"] = current_p7_slice

                # 2. Atualiza composto de pneus para a tabela de classificação
                max_status_cars = min(24, (data_len - 29) // car_status_size)
                for i in range(max_status_cars):
                    s_offset = 29 + (i * car_status_size)
                    if s_offset + comp_off < data_len:
                        c_id = data[s_offset + comp_off]
                        c_code, _, c_color = TYRE_MAP.get(c_id, ("M", "MÉDIO", "#eab308"))
                        cars_info[i]["compound"] = c_code
                        cars_info[i]["compound_color"] = c_color

            # ------------------------------------------
            # PACKET 10: CAR DAMAGE (DESGASTE DE PNEUS E ASAS)
            # ------------------------------------------
            elif packet_id == 10:
                car_damage_size = 46 if is_2026_pack or data_len >= 29 + (22 * 46) else 42
                damage_offset = 29 + (player_idx * car_damage_size)
                if damage_offset + 26 <= data_len:
                    # Desgaste dos pneus (4 floats: RL, RR, FL, FR)
                    rl_wear, rr_wear, fl_wear, fr_wear = struct.unpack_from('<4f', data, damage_offset)
                    telemetry["tyres"]["rl_wear"] = int(min(100, max(0, rl_wear)))
                    telemetry["tyres"]["rr_wear"] = int(min(100, max(0, rr_wear)))
                    telemetry["tyres"]["fl_wear"] = int(min(100, max(0, fl_wear)))
                    telemetry["tyres"]["fr_wear"] = int(min(100, max(0, fr_wear)))

                    # Danos das asas dianteiras (offset oficial 24=ESQ, 25=DIR)
                    fl_wing, fr_wing = struct.unpack_from('<BB', data, damage_offset + 28)
                    telemetry["wing_damage"]["fl"] = int(min(100, fl_wing))
                    telemetry["wing_damage"]["fr"] = int(min(100, fr_wing))
                    if damage_offset + 32 <= data_len:
                        udp_scanner["CAN_23_P10_DRS_Fault_B30"] = data[damage_offset + 30]
                        udp_scanner["CAN_24_P10_ERS_Fault_B31"] = data[damage_offset + 31]


        except Exception:
            pass


# ==========================================
# INTEGRAÇÃO ANDROID NATIVA (WEBVIEW TELA CHEIA)
# ==========================================
try:
    from kivy.app import App
    from kivy.uix.widget import Widget
    from kivy.clock import Clock
    import webbrowser

    class F1DashboardApp(App):
        def build(self):
            # No Android, inicializa o navegador / webview após o servidor subir
            Clock.schedule_once(self.open_ui, 1.5)
            return Widget()

        def open_ui(self, dt):
            try:
                from jnius import autoclass
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                Intent = autoclass('android.content.Intent')
                Uri = autoclass('android.net.Uri')
                intent = Intent(Intent.ACTION_VIEW, Uri.parse('http://127.0.0.1:5000'))
                currentActivity = PythonActivity.mActivity
                currentActivity.startActivity(intent)
            except Exception:
                webbrowser.open('http://127.0.0.1:5000')

    def start_android_app():
        t_udp = threading.Thread(target=udp_telemetry_listener, daemon=True)
        t_udp.start()
        t_http = threading.Thread(target=run_http_server, daemon=True)
        t_http.start()
        F1DashboardApp().run()

except ImportError:
    def start_android_app():
        t_udp = threading.Thread(target=udp_telemetry_listener, daemon=True)
        t_udp.start()
        run_http_server()

if __name__ == '__main__':
    start_android_app()
