#WIP -- FUCKING PERFECT KITING
import pydirectinput
import time
import pymem
import pymem.exception
import threading
import frida
import pyautogui
import bresenham
import json
import random
import tkinter as tk
from ttkthemes import ThemedTk
from pynput import mouse, keyboard
from tkinter import ttk
from queue import PriorityQueue
from pathlib import Path
import os, sys
from collections import deque
import math
import re


#memory addresses
walkAddress = "0xEEC70"
npcAddress = "0x1F450E"
directionalAddress = "0x6DACA"
EXP_HOOK_ADDR = 0x577414
varOffset = 0xA0

totalExp = None
WEIGHT_WRITE_ADDRS = [0x100DF5, 0x100454]
KILL_FLAG_DEBOUNCE = 0.25  
     
SPAWN_UID_OFFSET = 0xA0
MOB_ID_OFFSET = 0x98     # we read short at address_x - 0x98
MOB_ID_FILTERS = {285, 302, 188, 422, 538, 286, 292, 672, 301, 543, 325, 321, 319, 305, 502, 511, 512, 513, 514, 754, 413, 15, 324, 412, 84, 421, 422, 417}

# --- Configurable cleanup settings (GUI can edit these) ---
LAST_MOVED_TIMER_SECONDS = 35     # how long before unmoved NPC is stale
FLANK_RANGE = 1
INVALID_COORD_LIMIT = 100    # max valid X/Y (anything higher is junk)
POLL_INTERVAL = 0.05         # how often cleanup runs (seconds)
RANGE_MODE = {}

map_data_lock = threading.Lock()
SPEECH_ASSOC_RADIUS = 6          # tiles
SPEECH_TTL_S = 7.0               # bubble lifetime
recent_speech_log = deque(maxlen=120)
npc_last_speech = {}             # addr_hex -> {"text": str, "ts": float}
speech_quarantine_until = 0.0
TRIGGERS = [r'\bmax\b', r'\bnecklace\b', r'\b5\b']  # optional regex triggers

HARVEST_MODE = False
_harvest_thread = None
HARVEST_CANCEL = threading.Event()

# ═══════════════════════════════════════════════════════════════
# TASK MODE: Task management (replaces harvest mode)
# ═══════════════════════════════════════════════════════════════
TASK_MODE = False
_task_thread = None
TASK_CANCEL = threading.Event()
_task_loops_remaining = 1000
_tasks = []  # List of task dictionaries

# Blocked tile tracking (from npc4)
_task_temporary_blocked_tiles = {}  # tile -> expire_time
_task_permanent_blocked_tiles = set()  # permanently blocked tiles
_task_current_navigation_target = None  # Track final target for obstacle handling 
_task_last_success_direction = {}  # task key -> preferred facing direction

FACING_NAME_TO_CODE = {"DOWN": 0, "LEFT": 1, "UP": 2, "RIGHT": 3}
x_address = None
y_address = None
directional_address = None
combat_baseline_exp = None
current_target_npc = None
xstarted = 0
debug = 0
pyautogui.PAUSE = 0
last_direction = None
wandering_target = None
stuck_timer_start = None
last_position = None
pm = None  # Global pymem instance
pause_flag = False
stat_base = None  
CLICKING_ENABLED = True
resurrect_points = []
movement_allowed = threading.Event()
movement_allowed.set()
clicks_in_progress = threading.Event()
WANDER_TIMEOUT_S = 15.0  # max time to wander with no targets before re-running Home
game_win = None
STOP_HOME_IF_TARGET = True
IGNORE_PROTECTION = False          # False = protection ON, True = ignore (boss mode)
POST_PROTECT_GRACE_S = 2.0       # tiny debounce after protection ends


# ===================== HOME ROUTINE CONFIG =====================
HOME_POS = (3, 12)     # <<< SET THIS to your desired (X, Y) "home" tile
RUN_HOME_AFTER_KILL = True
HOME_NEAR_THRESH = 1       # distance in tiles considered "arrived
HOME_TRAVEL_TIMEOUT = 6.0  # seconds to give the walk before giving up
home_routine_running = threading.Event()
VANISH_GRACE_SEC = 0.0   # how long we wait after a target vanishes before assuming kill
RESPAWN_CHANGE_SEC = 0.4 # debounce if unique_id flips rapidly on respawn
WALKABLE_ARG = sys.argv[1] if len(sys.argv) > 1 else None
IMMUNITY_SEC = 0.0  # first N seconds to ignore death detection for a fresh target
_target_immunity_until = {}  # addr_hex -> monotonic deadline
BOSS_AGGRO_TOGGLE = True  # <<< Toggle for boss aggro detection during sitting
SIT_TIMER_SECONDS = 70   # <<< Configurable sit timer in seconds
CONFIG_FILE = "cerafrog_config.json"  # <<< Settings persistence file
KILL_QUARANTINE_SEC = 0.0        # keep a killed NPC muted for ~1s
RECENTLY_KILLED: dict[str, float] = {}  # addr_hex -> time.monotonic()
_last_kill_ts: dict[str, float] = {}
_kill_lock = threading.Lock()
KILL_DEBOUNCE_SEC = 0.25
DIRECTIONAL_LOOT = True          # pick 1 of 4, based on facing
LOOT_HOLD_SECONDS = 6.0          # how long to keep clicking that one spotp 
FAST_CLICK = False
FAST_CLICK_BURST_COUNT = 3
FAST_CLICK_GAP_S = 0.12 
ATTACK_RECENCY_S = 0.3
PRE_HIT_GRACE_S = 0.3
last_attack_time = 0.0
last_attack_addr = None
NO_CLICK_UNTIL = 0.0
F5_TAP_COUNT = 24
HOME_AFTER_KILLS_N = 1
KILLS_SINCE_HOME = 0
FORCE_MOVEMENT_SECONDS = 4.05
COMBAT_TASK_DURATION = 120          # default combat runtime in seconds
COMBAT_CLEAR_GRACE_SECONDS = 5.0    # how long area must stay empty before ending combat

DIR_TO_SLOT = {
    0: 2,  # 0 = Down  -> points[2]
    1: 3,  # 1 = Left  -> points[3]
    2: 0,  # 2 = Up    -> points[0]
    3: 1,  # 3 = Right -> points[1]
}


# Global bot control
bot_running = True  # <<< Global flag to control bot threads

        # ——— all stat offsets relative to EXP base ———
STAT_OFFSETS = {
        'exp':      0x000,   # at exp_base itself
        'weight':  -0x008,   # 0x0293F404
        'level':    0x008,   # 0x0293F414
        'tnl':      0x010,   # 0x0293F41C
        'eon':      0x034,   # 0x0293F440
        'vit':      0x188,   # 0x0293F594
        'dex':      0x184,   # 0x0293F590
        'acc':      0x180,   # 0x0293F58C
        'def':      0x17C,   # 0x0293F588
        'pwr':      0x178,   # 0x0293F584
        'crit':     0x174,   # 0x0293F580
        'armor':    0x170,   # 0x0293F57C
        'eva':      0x16C,   # 0x0293F578
        'hit_rate': 0x168,   # 0x0293F574
        'max_dmg':  0x164,   # 0x0293F570
        'min_dmg':  0x160,   # 0x0293F56C
        'aura':     0x18C,   # 0x0293F598
        'max_hp':   0x358,   # 0x0293F764
        'max_mana': 0x4F0,   # 0x0293F8FC
    }

def save_settings():
    """Save current settings to config file"""
    try:
        config = {
            "BOSS_AGGRO_TOGGLE": BOSS_AGGRO_TOGGLE,
            "SIT_TIMER_SECONDS": SIT_TIMER_SECONDS,
            "LAST_MOVED_TIMER_SECONDS": LAST_MOVED_TIMER_SECONDS,
            "MOB_ID_FILTERS": list(MOB_ID_FILTERS),
            "HOME_POS": HOME_POS,
            "FLANK_RANGE": FLANK_RANGE,
            "RUN_HOME_AFTER_KILL": RUN_HOME_AFTER_KILL,
            "CLICKING_ENABLED": CLICKING_ENABLED,
            "FAST_CLICK": FAST_CLICK,
            "FAST_CLICK_BURST_COUNT": FAST_CLICK_BURST_COUNT,
            "FAST_CLICK_GAP_S": FAST_CLICK_GAP_S,
            "IGNORE_PROTECTION": bool(globals().get("IGNORE_PROTECTION", False)),
            "F5_TAP_COUNT": int(F5_TAP_COUNT),               
            "WANDER_TIMEOUT_S": float(WANDER_TIMEOUT_S), 
            "HOME_AFTER_KILLS_N": int(HOME_AFTER_KILLS_N),
            "FORCE_MOVEMENT_SECONDS": float(FORCE_MOVEMENT_SECONDS),
            "RESURRECT_POINTS": list(resurrect_points),  # Save click locations [Up, Right, Down, Left]
            "COMBAT_TASK_DURATION": int(COMBAT_TASK_DURATION),
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[CONFIG] Settings saved to {CONFIG_FILE}")
    except Exception as e:
        print(f"[CONFIG] Failed to save settings: {e}")


def load_settings():
    global BOSS_AGGRO_TOGGLE, SIT_TIMER_SECONDS, LAST_MOVED_TIMER_SECONDS, MOB_ID_FILTERS, HOME_POS, FLANK_RANGE, RUN_HOME_AFTER_KILL, CLICKING_ENABLED, FAST_CLICK, FAST_CLICK_BURST_COUNT, FAST_CLICK_GAP_S, IGNORE_PROTECTION, HOME_AFTER_KILLS_N, F5_TAP_COUNT, WANDER_TIMEOUT_S, resurrect_points, COMBAT_TASK_DURATION
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)

            BOSS_AGGRO_TOGGLE = config.get("BOSS_AGGRO_TOGGLE", BOSS_AGGRO_TOGGLE)
            SIT_TIMER_SECONDS = config.get("SIT_TIMER_SECONDS", SIT_TIMER_SECONDS)
            LAST_MOVED_TIMER_SECONDS = config.get("LAST_MOVED_TIMER_SECONDS", LAST_MOVED_TIMER_SECONDS)
            MOB_ID_FILTERS = set(config.get("MOB_ID_FILTERS", list(MOB_ID_FILTERS)))
            HOME_POS = tuple(config.get("HOME_POS", list(HOME_POS)))
            RUN_HOME_AFTER_KILL = config.get("RUN_HOME_AFTER_KILL", RUN_HOME_AFTER_KILL)
            CLICKING_ENABLED = config.get("CLICKING_ENABLED", CLICKING_ENABLED)
            FAST_CLICK = config.get("FAST_CLICK", FAST_CLICK)
            FAST_CLICK_BURST_COUNT = int(config.get("FAST_CLICK_BURST_COUNT", FAST_CLICK_BURST_COUNT))
            FAST_CLICK_GAP_S = float(config.get("FAST_CLICK_GAP_S", FAST_CLICK_GAP_S))
            F5_TAP_COUNT = int(config.get("F5_TAP_COUNT", F5_TAP_COUNT))
            WANDER_TIMEOUT_S = float(config.get("WANDER_TIMEOUT_S", WANDER_TIMEOUT_S))
            HOME_AFTER_KILLS_N = int(config.get("HOME_AFTER_KILLS_N", HOME_AFTER_KILLS_N))

            v = config.get("FLANK_RANGE")
            if v is not None:
                FLANK_RANGE = int(v)

            IGNORE_PROTECTION = bool(config.get("IGNORE_PROTECTION", IGNORE_PROTECTION))  # <— ADD THIS
            COMBAT_TASK_DURATION = int(config.get("COMBAT_TASK_DURATION", COMBAT_TASK_DURATION))
            
            # Load click locations (resurrect_points) - [Up, Right, Down, Left]
            saved_points = config.get("RESURRECT_POINTS", [])
            if saved_points and len(saved_points) == 4:
                # Convert list of lists to list of tuples
                resurrect_points[:] = [tuple(p) if isinstance(p, list) else p for p in saved_points]
                print(f"[CONFIG] Click locations loaded: {resurrect_points}")

            print(f"[CONFIG] Settings loaded from {CONFIG_FILE}")
        else:
            print(f"[CONFIG] No config file found, using defaults")
    except Exception as e:
        print(f"[CONFIG] Failed to load settings: {e}")

# --- Unified live-XY navigation core (targets for combat & harvest) ---

from typing import Callable, Optional, Tuple, Protocol

# Keep these tunables (you can tweak to taste)
STEP_TIMEOUT_S = 0.20   # shorter = snappier; don't go too low or steps may miss
STEP_POLL_S    = 0.008  # faster polling confirms steps sooner
REPLAN_LIMIT   = 10      # how many failed replans before giving up

class Target(Protocol):
    def get_xy(self) -> Optional[Tuple[int,int]]: ...
    def is_valid(self) -> bool: ...
    def on_arrival(self) -> bool: ...

def _live_xy() -> Optional[Tuple[int,int]]:
    x, y = _get_xy_safe()
    if x is None or y is None: return None
    return (int(x), int(y))

def _nudge_toward(cur: Tuple[int,int], nxt: Tuple[int,int]) -> None:
    cx, cy = cur; nx, ny = nxt
    if nx > cx: press_key('right', 1, 0.02)
    elif nx < cx: press_key('left', 1, 0.02)
    elif ny > cy: press_key('down', 1, 0.02)
    elif ny < cy: press_key('up', 1, 0.02)

def _move_one_tile(cur: Tuple[int,int], nxt: Tuple[int,int]) -> bool:
    """Tap toward nxt and confirm we actually landed there via live XY."""
    import time as _t
    _nudge_toward(cur, nxt)
    deadline = _t.monotonic() + STEP_TIMEOUT_S
    while _t.monotonic() < deadline:
        xy = _live_xy()
        if xy == nxt:
            return True
        _t.sleep(STEP_POLL_S)
    return False  # step didn't complete

def _path_or_none(start: Tuple[int,int], goal: Tuple[int,int], walkable: set):
    path = astar_pathfinding(start, goal, walkable)
    if not path or len(path) < 2: return None
    return path

def go_to_target(
    target: Target,
    *,
    near_thresh: float = 0.6,
    timeout_s: float = 40.0,
    tag: str = "NAV",
) -> bool:
    """Watchdog-free navigation: only replans after a failed step.
    Integrated fixes:
      - Adjacency guard before choosing a direction (prevents backwards picks).
      - Early stop while holding if we've reached/passed the segment end.
      - Overshoot promotion: if we land further along the path, advance i instead of backtracking.
    """
    import time
    walkable = set(load_walkable_tiles())

    cur = _live_xy()
    if cur is None or cur not in walkable:
        print(f"[{tag}] invalid start XY {cur}; abort"); return False

    goal = target.get_xy()
    if goal is None:
        print(f"[{tag}] target has no position"); return False
    if goal not in walkable:
        print(f"[{tag}] goal {goal} not walkable"); return False

    t0 = time.time()

    while time.time() - t0 < timeout_s:
        if not target.is_valid():
            print(f"[{tag}] target invalid/despawned"); return False

        # Refresh goal (cheap for static harvest nodes)
        g = target.get_xy()
        if g is None:
            print(f"[{tag}] target lost"); return False
        goal = g

        # Arrival gate: near + action commits
        cur = _live_xy()
        if cur is not None and _distance_tiles(cur, goal) <= near_thresh:
            if target.on_arrival():
                return True

        if cur is None:
            continue

        path = _path_or_none(cur, goal, walkable)
        if path is None:
            print(f"[{tag}] no path {cur}->{goal}"); return False

        progressed = False
        # Stream straight segments up to 4 tiles to avoid micro-pauses
        i = 1
        while i < len(path):
            nxt = path[i]
            if nxt not in walkable:
                print(f"[{tag}] path step {nxt} not walkable"); return False

            # Build a straight run starting at current index
            run_end = i
            if i + 1 < len(path):
                dx0 = path[i][0] - path[i-1][0]
                dy0 = path[i][1] - path[i-1][1]
                while run_end + 1 < len(path):
                    ndx = path[run_end+1][0] - path[run_end][0]
                    ndy = path[run_end+1][1] - path[run_end][1]
                    # cap run len to 4 tiles total (i..run_end inclusive)
                    if (ndx, ndy) == (dx0, dy0) and (run_end - i) < 3:
                        run_end += 1
                    else:
                        break

            # Decide direction key from delta of the first step (adjacency guard)
            dx = path[i][0] - cur[0]
            dy = path[i][1] - cur[1]
            if abs(dx) + abs(dy) != 1:
                # Not adjacent anymore — replan from current position
                break
            if   dx > 0 and dy == 0: key = 'right'
            elif dx < 0 and dy == 0: key = 'left'
            elif dy > 0 and dx == 0: key = 'down'
            elif dy < 0 and dx == 0: key = 'up'
            else:
                break  # safety: non-cardinal (shouldn't happen)

            # Hold the key across the segment and poll live XY
            hold_key(key)
            # Keep your global STEP_TIMEOUT_S behavior, but allow early exit if we pass run_end
            deadline = time.monotonic() + STEP_TIMEOUT_S * max(1, (run_end - i + 1))
            try:
                while time.monotonic() < deadline:
                    xy = _live_xy()
                    if xy:
                        cur = xy
                        # If we've reached or progressed past run_end along this path, stop holding now
                        # 'past' means cur appears later in the same path sequence.
                        try:
                            idx_in_path = path.index(cur)
                            if idx_in_path >= run_end:
                                break
                        except ValueError:
                            # cur not on this computed path snapshot; keep polling until timeout
                            pass
                    # still aiming for exact run_end otherwise
                    if cur == path[run_end]:
                        break
                    time.sleep(STEP_POLL_S)
            finally:
                release_key(key)

            # Overshoot promotion: if we landed further along the path, advance i instead of backtracking
            promoted = False
            if cur in path:
                cur_idx = path.index(cur)
                if cur_idx >= i:
                    progressed = True
                    i = cur_idx + 1
                    promoted = True
                    if _distance_tiles(cur, goal) <= near_thresh:
                        if target.on_arrival():
                            return True

            if promoted:
                continue

            if cur == path[run_end]:
                progressed = True
                i = run_end + 1
                if _distance_tiles(cur, goal) <= near_thresh:
                    if target.on_arrival():
                        return True
                continue
            else:
                # fallback: single-tile nudge toward path[i]
                if not _move_one_tile(cur, path[i]):
                    cur = _live_xy() or cur
                    break
                cur = path[i]
                progressed = True
                i += 1
                if _distance_tiles(cur, goal) <= near_thresh:
                    if target.on_arrival():
                        return True
                continue

        # If we never moved during this path attempt, let the outer loop replan
        if not progressed:
            # small backoff to avoid hammering when path is unstable
            time.sleep(0.01)

    print(f"[{tag}] timeout navigating to {goal}")
    return False


def start_bot():
    """Start all bot threads"""
    global bot_running
    bot_running = True
    print("[BOT] Time to Kill Shit!")
    
def stop_bot():
    """Stop all bot threads"""
    global bot_running
    bot_running = False
    print("[BOT] STOP Damnit!")
    
def is_bot_running():
    """Check if the bot is currently running"""
    return bot_running

def _combat_targets_present() -> bool:
    """Return True if there are any combat-eligible NPCs currently visible."""
    try:
        with map_data_lock:
            snapshot = list(map_data)
    except Exception:
        snapshot = list(map_data)

    now = time.monotonic()
    for item in snapshot:
        if item.get("type") != "npc":
            continue
        uid = item.get("unique_id")
        if uid not in MOB_ID_FILTERS:
            continue
        addr_hex = item.get("addr_hex")
        if addr_hex and (now - RECENTLY_KILLED.get(addr_hex, 0.0)) < KILL_QUARANTINE_SEC:
            continue
        return True
    return False

def _run_combat_task(task, task_id, duration_s: int) -> bool:
    """Run combat until the area is clear or the timer expires."""
    was_running = is_bot_running()
    if not was_running:
        start_bot()
        time.sleep(0.2)  # allow combat thread to spin up

    start_ts = time.time()
    last_target_seen = time.time() if _combat_targets_present() else None
    reason = None
    success = True

    print(
        f"[TASK] Task #{task_id} Combat engagement started "
        f"(limit={'∞' if duration_s <= 0 else f'{duration_s}s'})"
    )

    try:
        while True:
            if TASK_CANCEL.is_set() or not TASK_MODE:
                reason = "cancelled"
                success = False
                break

            now = time.time()

            if duration_s > 0 and (now - start_ts) >= duration_s:
                reason = "timer"
                break

            if _combat_targets_present():
                last_target_seen = now
            else:
                if last_target_seen is None:
                    if (now - start_ts) >= COMBAT_CLEAR_GRACE_SECONDS:
                        reason = "cleared"
                        break
                elif (now - last_target_seen) >= COMBAT_CLEAR_GRACE_SECONDS:
                    reason = "cleared"
                    break

            if _sleep_with_cancel(0.5):
                reason = "cancelled"
                success = False
                break
    finally:
        if not was_running:
            stop_bot()
            _all_stop()

    if success:
        if reason == "timer":
            print(f"[TASK] Task #{task_id} Combat timer reached {duration_s}s — moving on.")
        elif reason == "cleared":
            print(
                f"[TASK] Task #{task_id} Combat area clear "
                f"(no targets for {COMBAT_CLEAR_GRACE_SECONDS:.1f}s)."
            )
        else:
            print(f"[TASK] Task #{task_id} Combat finished.")
    else:
        print(f"[TASK] Task #{task_id} Combat cancelled.")

    return success

def record_direction_points():
    """
    Prompts user to click 4 times: Up, Right, Down, Left.
    Stores them into global `resurrect_points` in that exact order.
    """
    global resurrect_points
    resurrect_points.clear()
    prompts = ["UP", "RIGHT", "DOWN", "LEFT"]
    print("[SETUP] Click the following in your game window when prompted.")
    from pynput import mouse

    captured = []

    def capture_one(label):
        print(f"   ➜ Click the {label} spot now...")
        def on_click(x, y, button, pressed):
            if pressed:
                captured.append((x, y))
                print(f"     {label} recorded at {(x, y)}")
                return False
        with mouse.Listener(on_click=on_click) as listener:
            listener.join()

    for lab in prompts:
        capture_one(lab)

    resurrect_points[:] = captured  # [Up, Right, Down, Left]
    print("[SETUP] Click points set (Up,Right,Down,Left):", resurrect_points)


# --- HARD FREEZE HELPERS ---
def _all_stop():
    """Release any keys that could cause movement/attacking."""
    for k in ('ctrl', 'up', 'down', 'left', 'right'):
        try:
            release_key(k)
        except Exception:
            pass
    # let keyUps register
    time.sleep(0.08)

def _pause_movement():
    """Fully pause movement & attacks during pickups/home routine."""
    try:
        movement_allowed.clear()  # gate combat_thread BEFORE we click
    except Exception:
        pass
    _all_stop()
    time.sleep(0.07)              # debounce to avoid in-flight taps

def _resume_movement():
    """Allow combat thread to continue (after clicks/routines)."""
    _all_stop()                   # belt-and-suspenders
    try:
        movement_allowed.set()
    except Exception:
        pass

def _quarantine_cleanup_loop():
    """Housekeeping: forget old RECENTLY_KILLED entries."""
    import time as _t
    while True:
        now = _t.monotonic()
        for k, ts in list(RECENTLY_KILLED.items()):
            if (now - ts) > KILL_QUARANTINE_SEC:
                RECENTLY_KILLED.pop(k, None)
        _t.sleep(0.25)  # light duty

def _sleep_cancellable(seconds: float, step: float = 0.05):
    import time
    end = time.monotonic() + float(seconds)
    while time.monotonic() < end:
        if HARVEST_CANCEL.is_set():
            break
        time.sleep(step)

def _sleep_with_cancel(seconds: float, step: float = 0.05) -> bool:
    """Sleep in small increments; return True if a cancel flag is set."""
    import time
    end = time.monotonic() + float(seconds)
    while time.monotonic() < end:
        if TASK_CANCEL.is_set() or not TASK_MODE:
            return True
        if HARVEST_CANCEL.is_set():
            return True
        time.sleep(step)
    return False

def block_clicks_for(seconds: float):
    import time
    global NO_CLICK_UNTIL
    NO_CLICK_UNTIL = max(NO_CLICK_UNTIL, time.monotonic() + float(seconds))
    
def _has_available_target() -> bool:
    """True if any valid target NPC is currently visible on the map."""
    try:
        if not STOP_HOME_IF_TARGET:
            return False
        if not map_data:
            return False
        # Filter to targetable npcs by your MOB_ID_FILTERS and ignore recently killed
        now = time.monotonic()
        valid = []
        for item in map_data:
            if item.get("type") != "npc":
                continue
            uid = item.get("unique_id")
            if uid not in MOB_ID_FILTERS:
                continue
            addr_hex = item.get("addr_hex")
            # Optional: ignore just-killed entries in the quarantine window
            if addr_hex and (now - RECENTLY_KILLED.get(addr_hex, 0.0)) < KILL_QUARANTINE_SEC:
                continue
            valid.append(item)
        return bool(valid)
    except Exception:
        return False

def is_attacking() -> bool:
    return bool(globals().get('ctrl_pressed', False))

def recently_attacking(addr: str | None, window: float = ATTACK_RECENCY_S) -> bool:
    return (addr is not None
            and addr == globals().get('last_attack_addr')
            and (time.time() - globals().get('last_attack_time', 0.0)) < window)

def read_stat(name):
    """
    Reads a single stat using STAT_OFFSETS and the global stat_base.
    """
    global stat_base
    if stat_base is None:
        return None
    addr = stat_base + STAT_OFFSETS[name]
    try:
        return pm.read_int(addr)
    except Exception:
        return None

def read_all_stats():
    """
    Reads all stats into a dictionary.
    """
    stats = {}
    for k in STAT_OFFSETS:
        stats[k] = read_stat(k)
    return stats

def update_stats_gui():
    """
    Updates GUI with current stats every 0.5s.
    """
    while True:
        if stat_base:
            stats = read_all_stats()
            if stats:
                # Example simple print (replace with your GUI update call)
                gui_text = (
                    f"EXP: {stats['exp']} | LVL: {stats['level']} | TNL: {stats['tnl']}\n"
                    f"HP: {stats['max_hp']} | MANA: {stats['max_mana']}\n"
                    f"DEF: {stats['def']} | PWR: {stats['pwr']} | CRIT: {stats['crit']}\n"
                )
                print(gui_text)   # replace with your GUI label update
        time.sleep(0.5)

def _read_facing_live() -> int | None:
    """Return current facing 0..3 from directional_address, or None if unavailable."""
    try:
        if directional_address and pm:
            return int(pm.read_uchar(directional_address)) & 3
    except Exception:
        pass
    return None

def tap_key(key_name: str, times: int = 1, gap: float = 0.08):
    """Best-effort key tap that works with your existing press/release or keyboard lib."""
    import time, sys
    for _ in range(times):
        try:
            if 'press_key' in globals() and 'release_key' in globals():
                press_key(key_name)
                time.sleep(0.03)
                release_key(key_name)
            elif 'keyboard' in sys.modules:
                import keyboard
                keyboard.press_and_release(key_name)
            else:
                print(f"[WARN] No key sender available for {key_name}")
        except Exception as e:
            print(f"[WARN] tap_key({key_name}) failed: {e}")
        time.sleep(gap)

# ═══════════════════════════════════════════════════════════════
# TASK MODE: Helper functions for reading position/direction from CeraBot addresses
# ═══════════════════════════════════════════════════════════════

def _read_player_position_cerabot():
    """Read player position from CeraBot's direct memory addresses"""
    global pm, x_address, y_address
    try:
        if pm and x_address and y_address:
            x = pm.read_short(x_address)
            y = pm.read_short(y_address)
            return (int(x), int(y))
    except Exception as e:
        print(f"⚠️ Error reading position: {e}")
    return None

def _read_player_direction_cerabot():
    """Read player direction from CeraBot's direct memory address"""
    global pm, directional_address
    try:
        if pm and directional_address:
            dir_bytes = pm.read_bytes(directional_address, 1)
            if dir_bytes and len(dir_bytes) > 0:
                d = dir_bytes[0] & 3  # Mask to 0-3
                if 0 <= d <= 3:
                    return d
    except Exception as e:
        print(f"⚠️ Error reading direction: {e}")
    return None

def _read_player_state_cerabot():
    """Read full player state (x, y, direction) - compatible with npc4's scanner interface"""
    pos = _read_player_position_cerabot()
    if pos is None:
        return None
    direction = _read_player_direction_cerabot()
    if direction is None:
        return None
    return (pos[0], pos[1], direction)

def _get_xy_safe():
    """Try to read player coords if your script exposes it; otherwise return (None, None)."""
    # Only call if present
    fn = globals().get("get_player_coords")
    if callable(fn):
        try:
            return fn(pm)
        except Exception:
            pass
    try:
        return (pm.read_short(x_address), pm.read_short(y_address))
    except Exception:
        return (None, None)


def _distance_tiles(a, b):
    if a[0] is None or b[0] is None:
        return None
    dx = a[0] - b[0]
    dy = a[1] - b[1]
    return (dx*dx + dy*dy) ** 0.5

def _call_first_available(fn_names, *args):
    """Try a list of possible movement functions that may exist in your codebase."""
    for name in fn_names:
        fn = globals().get(name)
        if callable(fn):
            try:
                # Try (x, y) signature, fall back to ((x,y),) if needed
                try:
                    return fn(*args)
                except TypeError:
                    return fn(args[0])
            except Exception as e:
                print(f"[WARN] {name}{args} failed: {e}")
    raise RuntimeError("No compatible movement function found. "
                       "Implement one of: walk_to_tile / walk_to / navigate_to / move_to_tile / goto_tile")

def _go_to_home_blocking():
    """Walk to HOME_POS using the live navigator; abort early if targets appear."""
    if not isinstance(HOME_POS, tuple) or len(HOME_POS) != 2:
        print("[HOME] HOME_POS not set. Skipping travel.")
        return "SKIP"

    # Abort before starting if a target is already visible
    if _has_available_target():
        print("[HOME] Abort: target spotted before travel.")
        return "ABORT"

    hx, hy = int(HOME_POS[0]), int(HOME_POS[1])

    class _HomeTarget:
        def get_xy(self):            # navigator asks where to go
            return (hx, hy)
        def is_valid(self):          # always a valid goal
            return True
        def on_arrival(self):        # nothing special on arrival
            return True

    # Use the same pathing as harvest/combat so we follow walkable.json
    try:
        go_to_target(_HomeTarget(), tag="HOME",
                     near_thresh=globals().get("HOME_NEAR_THRESH", 0.8),
                     timeout_s=globals().get("HOME_TRAVEL_TIMEOUT", 30.0))
    except Exception as e:
        print(f"[HOME] Navigator error: {e!r}")
        return "TIMEOUT"

    # Poll until close or timeout so the caller gets a status (kept from old flow)
    import time
    start = time.time()
    HOME_TRAVEL_TIMEOUT = float(globals().get("HOME_TRAVEL_TIMEOUT", 30.0))
    HOME_NEAR_THRESH    = float(globals().get("HOME_NEAR_THRESH", 0.8))
    while time.time() - start < HOME_TRAVEL_TIMEOUT:
        # abort if a target pops up during the trip
        if _has_available_target():
            print("[HOME] Abort: target spotted during travel.")
            return "ABORT"
        cur = _get_xy_safe()
        dist = _distance_tiles(cur, (hx, hy))
        if dist is not None and dist <= HOME_NEAR_THRESH:
            print(f"[HOME] Arrived at HOME {HOME_POS}")
            return "ARRIVED"
        time.sleep(0.2)

    print("[HOME] Travel timeout.")
    return "TIMEOUT"


def _home_routine():
    """
    Pause combat/wandering, wait for any pickup clicks to finish,
    go home, run F11/F5 sequence (interruptible), then resume.

    Behavior:
      - If a target is visible at ANY point, immediately abort buffs/sit and resume combat.
      - Travel to home can also abort early if a target appears (handled in _go_to_home_blocking()).
      - F5 is applied in small steps so the routine can bail out mid-buff.
    """
    if home_routine_running.is_set():
        return
    home_routine_running.set()
    print("[HOME] Starting safety routine…")

    # Helper: wait until clicks are done (with a safety timeout)
    def _wait_for_clicks(label: str, timeout_s: float = 6.0):
        try:
            start = time.time()
            while clicks_in_progress.is_set():
                if timeout_s and (time.time() - start) > timeout_s:
                    print(f"[HOME] {label}: waited {timeout_s}s for clicks; continuing.")
                    break
                time.sleep(0.01)
        except NameError:
            # clicks_in_progress not defined; nothing to wait for
            pass

    def _finish():
        # Resume normal behavior and clear guard
        try:
            _resume_movement()
        except Exception:
            pass
        home_routine_running.clear()

    try:
        # If a loot sweep is in progress, wait for it to finish
        _wait_for_clicks("pre-travel")

        # Freeze movement/attacks
        try:
            _pause_movement()
        except Exception:
            pass
        try:
            release_key('ctrl')
        except Exception:
            pass

        # Focus game window if available (best-effort)
        try:
            if game_win:
                try:
                    game_win.activate()
                    time.sleep(0.2)
                except Exception:
                    pass
        except NameError:
            pass

        # ——— Immediate abort if a target is already available ———
        try:
            if _has_available_target():
                print("[HOME] Abort: target visible before travel; resuming combat.")
                return
        except NameError:
            # If helper/toggle not present, fall back to legacy flow
            pass

        # ——— Travel to home tile (blocking & abortable) ———
        travel_status = None
        try:
            travel_status = _go_to_home_blocking()
        except Exception as e:
            print(f"[HOME] Travel error: {e!r}")
            travel_status = "TIMEOUT"

        if travel_status in ("ABORT",):
            print("[HOME] Travel aborted due to target; resuming combat.")
            return
        if travel_status in ("SKIP", "TIMEOUT"):
            try:
                if _has_available_target():
                    print("[HOME] Target visible after travel failure; resuming combat.")
                    return
            except NameError:
                pass
            # Force the normal sit/buff flow to run *right here* on timeout
            print(f"[HOME] Travel status={travel_status}; forcing sit/buffs here.")
            # (no return — fall through to the F11/F5 sit/buff logic below

        # Just in case a new click sweep started during travel, wait again
        _wait_for_clicks("pre-buff")

        # ——— Abort if target visible before sit/buffs ———
        try:
            if _has_available_target():
                print("[HOME] Abort: target visible pre-buff; resuming combat.")
                return
        except NameError:
            pass

        # ——— F11 (sit), then F5 in small, interruptible steps ———
        try:
            tap_key('f11', times=1)
            block_clicks_for(3.0)
        except Exception:
            pass

        # Apply F5 up to 24 taps, but interrupt if a target appears
        f5_total = int(globals().get("F5_TAP_COUNT", 24))
        f5_gap = 0.08
        for i in range(f5_total):
            try:
                if _has_available_target():
                    print(f"[HOME] Abort: target visible during buffs at F5#{i+1}; skipping rest.")
                    break
            except NameError:
                # If no helper, just run the full sequence
                pass
            try:
                tap_key('f5', times=1, gap=f5_gap)
            except Exception:
                # Keep going even if a single tap fails
                pass

        # ——— Wait up to SIT_TIMER_SECONDS, but bail early if targets appear ———
        try:
            sit_secs = int(SIT_TIMER_SECONDS)
        except NameError:
            sit_secs = 10

        print(f"[HOME] Waiting up to {sit_secs}s (interruptible).")

        try:
            if BOSS_AGGRO_TOGGLE:
                for i in range(SIT_TIMER_SECONDS):
                    try:
                        if _has_available_target():
                            remaining_time = SIT_TIMER_SECONDS - i
                            print(f"[HOME] Target detected! Cutting wait short by {remaining_time}s.")
                            break
                    except NameError:
                        # Fallback: scan map_data without helper if available
                        try:
                            if map_data:
                                npcs = [it for it in map_data if it.get("type") == "npc"]
                                valid = [n for n in npcs if n.get("unique_id") in MOB_ID_FILTERS]
                                if valid:
                                    remaining_time = SIT_TIMER_SECONDS - i
                                    print(f"[HOME] Target detected! Cutting wait short by {remaining_time}s.")
                                    break
                        except NameError:
                            # Nothing we can do; just wait the full time
                            pass
                    time.sleep(1)
        except NameError:
            # If toggle missing, do nothing (no wait).
            pass

        # ——— Stand up (F11). If a target is present, we're already about to resume. ———
        try:
            tap_key('f11', times=1)
        except Exception:
            pass
        
        # reset kill counter after a full sit/buff cycle
        try:
            globals()['KILLS_SINCE_HOME'] = 0
            print(f"[HOME] Kill counter reset.")
        except Exception:
            pass

        print("[HOME] Safety sequence complete; resuming combat.")

    finally:
        _finish()


def _in_immunity(addr_hex: str) -> bool:
    """True if addr_hex is inside the 'first N seconds after attach' window."""
    try:
        import time as _t
        if not addr_hex:
            return False
        deadline = _target_immunity_until.get(addr_hex, 0.0)
        return _t.monotonic() < deadline
    except Exception:
        return False

def _fire_kill_once(addr_hex: str, reason: str) -> bool:
    """
    Run kill actions only if addr_hex == current_target_npc, and at most once per debounce/quarantine window.
    """
    import time
    global current_target_npc

    if not addr_hex or addr_hex != current_target_npc:
        return False

    # hard block if we're already busy with kill/home
    try:
        if home_routine_running.is_set() or clicks_in_progress.is_set():
            return False
    except Exception:
        pass

    now = time.monotonic()


    last_k = RECENTLY_KILLED.get(addr_hex, 0.0)
    if (now - last_k) < KILL_QUARANTINE_SEC:
        return False

    # existing micro-debounce (keeps rapid re-entrance out)
    prev = _last_kill_ts.get(addr_hex, 0.0)
    if (now - prev) < KILL_DEBOUNCE_SEC:
        return False

    with _kill_lock:
        prev = _last_kill_ts.get(addr_hex, 0.0)
        if (now - prev) < KILL_DEBOUNCE_SEC:
            return False

        # Mark both the short debounce and the quarantine *before* calling _on_kill
        _last_kill_ts[addr_hex] = now
        RECENTLY_KILLED[addr_hex] = now

        _on_kill(addr_hex, reason=reason)
        return True


def on_message_exp(message, data):
    global stat_base
    if message['type'] == 'send':
        payload = message['payload']
        base_str = payload.get('exp_address')
        if base_str:
            try:
                stat_base = int(base_str, 16)

                # Kill trigger on EXP hook (only once, only for our current target)
                if current_target_npc:
                    _fire_kill_once(current_target_npc, reason="EXP-HOOK")
                    

            except Exception as e:
                print(f"[frida] Failed to parse stat base: {e}")

def _on_kill(addr_hex: str, reason: str):
    global current_target_npc  # must be declared at the very top

    # --- timestamp helper ---
    def _ts():
        import time
        return time.strftime("%H:%M:%S")

    print(f"[KILLS][{_ts()}] KILLED: {addr_hex if addr_hex else '0x0'} | {reason}")

    # Record kill time for duplicate/vanish heuristics (best-effort)
    try:
        import time as _t
        if addr_hex:
            RECENTLY_KILLED[addr_hex] = _t.monotonic()
    except Exception:
        pass

    # --- PER-KILL FAST-SKIP (run this BEFORE any pausing/gating) ---
    try:
        clicking_disabled = not globals().get("CLICKING_ENABLED", True)
        run_home = bool(globals().get("RUN_HOME_AFTER_KILL", False))
        fast_click_enabled = bool(globals().get("FAST_CLICK", False))   # <-- NEW
    except Exception:
        clicking_disabled, run_home, fast_click_enabled = False, False, False

    if clicking_disabled and (not fast_click_enabled) and (not run_home):
        # No pause, no gating flags, no sleeps — just clean up & let combat retarget immediately.
        try:
            # Make sure any ctrl is released but don't pause movement.
            try:
                release_key('ctrl')
            except Exception:
                pass

            # Remove the dead target from tracking so the chooser can immediately pick a new one.
            if 'manager' in globals() and manager and addr_hex:
                manager.remove_address(addr_hex)
        except Exception:
            pass

        try:
            if addr_hex and 'vanish_timer' in globals():
                globals().get('vanish_timer', {}).pop(addr_hex, None)
            current_target_npc = None
        except Exception:
            pass

        # No sleep, no clicks_in_progress gate here.
        print(f"[KILL] Training Mode — home disabled, immediate resume (addr={addr_hex})")
        return

    # Stop movement and make sure CTRL isn't held (this only runs if we DO need loot/home)
    try:
        _pause_movement()
    except Exception:
        pass
    try:
        release_key('ctrl')
    except Exception:
        pass
    # --- end fast-skip ---

    # Try to bring game window front
    try:
        import pyautogui
        windows = pyautogui.getWindowsWithTitle("Endless")
        game_win = windows[0] if windows else None
    except Exception:
        game_win = None

    # Facing from live data
    facing = 0
    try:
        facing = int(player_data_manager.get_data().get("direction", 0))
    except Exception:
        pass

    # Saved points
    pts = list(globals().get("resurrect_points", []))

    try:
        # If Fast Click is enabled, do the burst instead of the 6s hold
        if bool(globals().get("FAST_CLICK", False)) and (not globals().get("CLICKING_ENABLED", True)):
            _do_fast_click_burst(
                game_win, 
                pts, 
                facing, 
                int(globals().get("FAST_CLICK_BURST_COUNT", 6)),
                float(globals().get("FAST_CLICK_GAP_S", 0.12)),
                tag="KILL"
            )
        elif DIRECTIONAL_LOOT:
            _do_directional_loot(game_win, pts, facing, hold_seconds=LOOT_HOLD_SECONDS, tag="KILL")
        else:
            _do_clicks(game_win, pts, tag="KILL")
    except Exception:
        pass

    # Run home or resume movement (with kill threshold)
    try:
        run_home_toggle = RUN_HOME_AFTER_KILL if 'RUN_HOME_AFTER_KILL' in globals() else True

        # count this kill
        try:
            globals()['KILLS_SINCE_HOME'] = int(globals().get('KILLS_SINCE_HOME', 0)) + 1
        except Exception:
            globals()['KILLS_SINCE_HOME'] = 1

        should_home_now = (
            run_home_toggle
            and not home_routine_running.is_set()
            and int(globals().get('KILLS_SINCE_HOME', 0)) >= int(globals().get('HOME_AFTER_KILLS_N', 1))
        )

        if should_home_now:
            print(f"[KILLS] Threshold reached: {globals().get('KILLS_SINCE_HOME', 0)} / {globals().get('HOME_AFTER_KILLS_N', 1)} → going Home")
            threading.Thread(target=_home_routine, daemon=True).start()
        else:
            _resume_movement()
    except Exception:
        pass

    # Cleanup tracking
    try:
        if 'manager' in globals() and manager and addr_hex:
            manager.remove_address(addr_hex)
    except Exception:
        pass

    try:
        if addr_hex and 'vanish_timer' in globals():
            globals().get('vanish_timer', {}).pop(addr_hex, None)
        current_target_npc = None
    except Exception:
        pass

# ---------------- HARVEST MODE (click / mine / chop) ----------------


def _load_harvest_nodes():
    j, _p = load_walkable_json()
    out = []
    for n in j.get("harvest_nodes", []):
        try:
            x, y = int(n["x"]), int(n["y"])
            kind = str(n.get("type", "click")).lower()
            assert kind in ("click", "mine", "chop")
            face = (n.get("facing") or "").upper() or None
            default_hold = 6.0 if kind in ("mine","chop") else float(globals().get("LOOT_HOLD_SECONDS", 2.5))
            hold = float(n.get("hold_seconds", default_hold))
            out.append({"x": x, "y": y, "type": kind, "facing": face, "hold": hold})
        except Exception as e:
            print(f"[HARVEST] bad node {n}: {e}")
    return out

def _desired_facing_for_tile(px, py, tx, ty, facing_override):
    if facing_override:
        return FACING_NAME_TO_CODE.get(facing_override, 0)
    dx, dy = tx - (px or tx), ty - (py or ty)
    if abs(dy) >= abs(dx):  # prefer vertical on tie
        return 0 if dy > 0 else 2   # Down/Up
    return 3 if dx > 0 else 1       # Right/Left


def _get_game_window():
    try:
        import pyautogui
        wins = pyautogui.getWindowsWithTitle("Endless")
        return wins[0] if wins else None
    except Exception:
        return None

def _face_in_game_best_effort(facing: int):
    """Turn without stepping: only micro-tap if facing differs."""
    try:
        want = int(facing) % 4

        # If we can read current facing and it already matches, do nothing.
        cur = _read_facing_live()
        if cur is not None and (cur % 4) == want:
            return

        dir_key = {0:'down', 1:'left', 2:'up', 3:'right'}[want]

        # ensure no arrow is being held
        for k in ('up','down','left','right'):
            try: release_key(k)
            except Exception: pass

        # micro-tap (shorter than a movement tick; you can try 0.006–0.012)
        hold_key(dir_key)
        time.sleep(0.008)
        release_key(dir_key)
    except Exception:
        pass

def _click_directional_for_facing(game_win, facing, hold_seconds, tag="HARVEST"):
    # Ensure we have 4 recorded points in Up,Right,Down,Left order
    pts = list(globals().get("resurrect_points", []))
    if not pts or len(pts) < 4:
        print("[HARVEST] Run record_direction_points() first.")
        return

    facing = int(facing) % 4
    slot = DIR_TO_SLOT.get(facing, 0)
    cx, cy = pts[slot if slot < len(pts) else 0]
    print(f"[{tag}] facing={facing} slot={slot} -> click@({cx},{cy}) for {hold_seconds:.2f}s")

    # Try to focus the game so clicks land
    try:
        if game_win:
            game_win.activate()
            time.sleep(0.15)
    except Exception:
        pass

    # If global clicking is enabled, use the normal directional routine
    try:
        if globals().get("CLICKING_ENABLED", True) and globals().get("DIRECTIONAL_LOOT", True):
            _do_directional_loot(game_win, pts, facing, hold_seconds=hold_seconds, tag=tag)
            return
    except Exception:
        # fall through to manual clicks
        pass

    # Otherwise (e.g., CLICKING_ENABLED == False), do a minimal direct click anyway so harvest works
    try:
        import pydirectinput
        # small burst + hold-like wait to mimic press/hold behavior on some nodes
        for _ in range(3):
            if HARVEST_CANCEL.is_set(): break
            pydirectinput.click(x=cx, y=cy)
            _sleep_cancellable(0.10)
        _sleep_cancellable(hold_seconds)
    except Exception as e:
        print(f"[{tag}] fallback click failed: {e}")



def _harvest_action(kind, facing, hold):
    gw = _get_game_window()
    _face_in_game_best_effort(facing)

    if kind == "click":
        _click_directional_for_facing(gw, facing, hold, tag="HARVEST/CLICK")
        return

    # mine/chop: tool hotkey then hold CTRL
    try:
        if kind == "mine": tap_key('f1', times=1)
        elif kind == "chop": tap_key('f2', times=1)
    except Exception:
        pass
    import time
    try:
        hold_key('ctrl')
        _sleep_cancellable(float(hold))   # instead of time.sleep(hold)
        release_key('ctrl')
    finally:
        try: release_key('ctrl')
        except Exception: pass

def _neighbors_cardinal(x:int, y:int):
    # Up, Right, Down, Left
    return [(x, y-1), (x+1, y), (x, y+1), (x-1, y)]

def _load_walkable_tiles_as_set():
    """Load walkable tiles using CeraBot's load_walkable_tiles() function - returns set of (x,y) tuples"""
    try:
        # load_walkable_tiles() already returns a set of (x, y) tuples from walkable.json
        return load_walkable_tiles()
    except Exception as e:
        print(f"⚠️ Error loading walkable tiles: {e}")
        return set()

# ═══════════════════════════════════════════════════════════════
# TASK MODE: Pathfinding and Navigation (from npc4, adapted for CeraBot)
# ═══════════════════════════════════════════════════════════════

def _astar_pathfinding_cerabot(start, goal, walkable_tiles, allow_unwalkable_bias=False):
    """A* pathfinding adapted from npc4 for CeraBot - allows unwalkable tiles if necessary to reach goal"""
    if start == goal:
        return [start]
    
    # CRITICAL: Start position is ALWAYS valid - if we're there, we can read it from memory, so it's walkable
    # The walkable.json file may not contain all walkable tiles, but if we're at a position, it's definitely walkable
    # Always allow both start and goal positions
    working_walkable = walkable_tiles.copy()
    working_walkable.add(start)  # Start is ALWAYS valid (we're already there - bot walked there)
    working_walkable.add(goal)   # Goal is always allowed (user may want to walk to specific coordinates)
    
    # If goal is not in original walkable set, we'll dynamically allow unwalkable tiles
    # that get us closer to the goal during pathfinding
    goal_in_original = goal in walkable_tiles
    if not goal_in_original:
        print(f"⚠️ A*: Goal {goal} not in walkable tiles, will allow unwalkable tiles in path if necessary")
    
    try:
        open_set = PriorityQueue()
        open_set.put((0, start))
        came_from = {}
        g_score = {start: 0}
        
        def heuristic(a, b):
            return abs(a[0] - b[0]) + abs(a[1] - b[1])
        
        f_score = {start: heuristic(start, goal)}
        explored_count = 0
        max_explorations = min(len(working_walkable) * 3, 5000)  # Increased exploration limit
        
        # Track which tiles are actually unwalkable (for penalty)
        original_walkable_set = walkable_tiles
        
        while not open_set.empty() and explored_count < max_explorations:
            explored_count += 1
            
            try:
                _, current = open_set.get()
            except Exception as e:
                print(f"❌ A* priority queue error: {e}")
                return None
            
            if current == goal:
                # Reconstruct path
                path = []
                while current in came_from:
                    path.append(current)
                    current = came_from[current]
                path.append(start)
                path.reverse()
                
                if len(path) < 2:
                    print(f"❌ A* produced invalid path: {path}")
                    return None
                
                # Check if path uses unwalkable tiles
                unwalkable_in_path = [tile for tile in path if tile not in original_walkable_set and tile != goal]
                if unwalkable_in_path:
                    print(f"⚠️ A* path uses {len(unwalkable_in_path)} unwalkable tiles: {unwalkable_in_path[:5]}")
                
                print(f"✅ A* found path of length {len(path)} after {explored_count} explorations")
                return path
            
            # Check all 4 directions
            directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
            for dx, dy in directions:
                try:
                    neighbor = (current[0] + dx, current[1] + dy)
                    
                    # Use working_walkable which includes goal
                    # If goal is unwalkable, allow unwalkable tiles that get us closer to goal
                    if neighbor not in working_walkable:
                        if allow_unwalkable_bias:
                            current_dist = abs(current[0] - goal[0]) + abs(current[1] - goal[1])
                            neighbor_dist = abs(neighbor[0] - goal[0]) + abs(neighbor[1] - goal[1])
                            if neighbor_dist <= current_dist + 2:
                                working_walkable.add(neighbor)
                            else:
                                continue
                        elif not goal_in_original:
                            # Calculate distance to goal - allow if it gets us closer
                            current_dist = abs(current[0] - goal[0]) + abs(current[1] - goal[1])
                            neighbor_dist = abs(neighbor[0] - goal[0]) + abs(neighbor[1] - goal[1])
                            # Allow unwalkable tile if it's closer to goal (or same distance but different path)
                            if neighbor_dist <= current_dist + 1:  # Allow if same distance or closer
                                working_walkable.add(neighbor)
                            else:
                                continue
                        else:
                            continue
                    
                    step_cost = 1
                    if neighbor not in original_walkable_set:
                        step_cost = 3 if allow_unwalkable_bias else 1
                    
                    tentative_g_score = g_score[current] + step_cost
                    
                    if neighbor not in g_score or tentative_g_score < g_score[neighbor]:
                        came_from[neighbor] = current
                        g_score[neighbor] = tentative_g_score
                        f_score[neighbor] = tentative_g_score + heuristic(neighbor, goal)
                        open_set.put((f_score[neighbor], neighbor))
                        
                except Exception as e:
                    print(f"❌ A* neighbor processing error: {e}")
                    continue
        
        print(f"❌ A* failed after {explored_count} explorations")
        return None
        
    except Exception as e:
        print(f"❌ A* critical error: {e}")
        return None

def _try_direct_movement_to_target_cerabot(current_pos, target_pos, max_attempts=50, warp_mode=False):
    """Try direct movement toward goal using arrow keys when pathfinding fails - with obstacle avoidance"""
    import time
    import pydirectinput
    
    print(f"🎯 DIRECT MOVEMENT: Attempting to move from {current_pos} → {target_pos}")
    
    # Get walkable tiles for obstacle handling
    walkable_tiles = _load_walkable_tiles_as_set()
    if not walkable_tiles:
        walkable_tiles = set()  # Use empty set if can't load
    
    attempt = 0
    consecutive_failures = 0  # Track consecutive failures in same direction
    last_failed_direction = None
    obstacle_stage = 0  # Track which obstacle handling stage we're on
    near_distance_threshold = 2
    teleport_distance_threshold = 8
    warp_recently_near = False
    warp_was_near = False
    warp_steps_since_near = 0
    final_target_block_count = 0
    
    while attempt < max_attempts:
        if TASK_CANCEL.is_set():
            print("❌ DIRECT: Task cancelled")
            return False
        
        attempt += 1
        
        # Check current position
        current_check = _read_player_position_cerabot()
        if not current_check:
            print("❌ DIRECT: Cannot read position")
            return False
        
        # Check if we reached target
        if current_check == target_pos:
            print(f"✅ DIRECT: Reached target after {attempt} attempts!")
            return True
        
        dist_to_target = abs(current_check[0] - target_pos[0]) + abs(current_check[1] - target_pos[1])
        if warp_mode:
            if dist_to_target <= near_distance_threshold:
                warp_recently_near = True
                warp_was_near = True
                warp_steps_since_near = 0
            elif warp_recently_near:
                warp_steps_since_near += 1
                if warp_steps_since_near > 4:
                    warp_recently_near = False
        
        # Calculate direction toward target
        x_diff = target_pos[0] - current_check[0]
        y_diff = target_pos[1] - current_check[1]
        
        # Determine best direction (prioritize larger difference)
        direction = None
        if abs(x_diff) > abs(y_diff):
            direction = "right" if x_diff > 0 else "left"
        else:
            direction = "down" if y_diff > 0 else "up"
        
        # If we're very close (within 1 tile), try to reach it
        if abs(x_diff) <= 1 and abs(y_diff) <= 1:
            if x_diff != 0:
                direction = "right" if x_diff > 0 else "left"
            elif y_diff != 0:
                direction = "down" if y_diff > 0 else "up"
            else:
                # Already at target (shouldn't happen, but check anyway)
                return True
        
        # Calculate next position we're trying to reach
        next_pos = current_check
        if direction == "right":
            next_pos = (current_check[0] + 1, current_check[1])
        elif direction == "left":
            next_pos = (current_check[0] - 1, current_check[1])
        elif direction == "down":
            next_pos = (current_check[0], current_check[1] + 1)
        elif direction == "up":
            next_pos = (current_check[0], current_check[1] - 1)
        
        # If we've failed multiple times in the same direction, use obstacle handling
        if (consecutive_failures >= 2 and direction == last_failed_direction) and not TASK_CANCEL.is_set():
            obstacle_stage += 1
            if obstacle_stage > 6:
                obstacle_stage = 1  # Reset to stage 1 after going through all stages
            
            print(f"🚫 DIRECT: Obstacle detected - engaging obstacle handling stage {obstacle_stage}")
            success, action, result = _handle_movement_obstacle_cerabot(
                current_check, next_pos, direction, obstacle_stage, walkable_tiles, target_pos
            )
            
            if success:
                if action == "continue":
                    # Obstacle handled, try moving again
                    consecutive_failures = 0
                    last_failed_direction = None
                    # Re-read position after obstacle handling
                    current_check = _read_player_position_cerabot()
                    if current_check == target_pos:
                        return True
                    continue
                elif action == "use_alternative_path":
                    # Alternative path found - but we're in direct movement mode, so just continue
                    consecutive_failures = 0
                    last_failed_direction = None
                    continue
                elif action == "recompute_path":
                    # Try to recompute - but we're in direct mode, so just continue
                    consecutive_failures = 0
                    last_failed_direction = None
                    continue
                elif action == "next_stage":
                    if next_pos == target_pos:
                        final_target_block_count += 1
                        if final_target_block_count > 1:
                            print("🚫 DIRECT: Final tile still blocked after force attempts; trying alternate route")
                            return False
                    consecutive_failures += 1
                    time.sleep(0.3)
                    continue
                elif action == "abort":
                    print("❌ DIRECT: Obstacle handling aborted")
                    return False
            else:
                # Obstacle handling failed, continue trying
                consecutive_failures += 1
                time.sleep(0.3)
                continue
        
        fast_movement = dist_to_target > 3
        print(f"🎮 DIRECT: Attempt {attempt}/{max_attempts} - moving {direction} (diff: {x_diff}, {y_diff})")
        
        try:
            # Switch to game window
            _switch_to_game_window()
            
            # Execute movement step with appropriate speed
            _perform_movement_step(direction, fast_movement)
            
            # Wait and check if we moved
            time.sleep(0.05 if fast_movement else 0.15)
            new_pos = _read_player_position_cerabot()
            
            if new_pos:
                if new_pos == target_pos:
                    print(f"✅ DIRECT: Reached target after {attempt} attempts!")
                    return True
                if warp_mode and warp_recently_near:
                    new_distance = abs(new_pos[0] - target_pos[0]) + abs(new_pos[1] - target_pos[1])
                    if new_distance >= teleport_distance_threshold:
                        print("🌀 DIRECT: Detected warp teleport during direct movement")
                        return True
                elif new_pos != current_check:
                    print(f"✅ DIRECT: Moved to {new_pos} (distance: {abs(new_pos[0] - target_pos[0]) + abs(new_pos[1] - target_pos[1])})")
                    current_check = new_pos
                    consecutive_failures = 0  # Reset failure counter on successful movement
                    last_failed_direction = None
                    obstacle_stage = 0  # Reset obstacle stage
                else:
                    print(f"⚠️ DIRECT: No movement detected on attempt {attempt}")
                    consecutive_failures += 1
                    last_failed_direction = direction
                    time.sleep(0.2)
            else:
                if warp_mode and warp_recently_near:
                    print("🌀 DIRECT: Warp teleport suspected (position temporarily unavailable after move)")
                    return True
                print(f"⚠️ DIRECT: Could not read position after movement")
                consecutive_failures += 1
                last_failed_direction = direction
                time.sleep(0.2)
                
        except Exception as e:
            print(f"❌ DIRECT: Movement error on attempt {attempt}: {e}")
            consecutive_failures += 1
            last_failed_direction = direction
            time.sleep(0.2)
    
    if warp_mode and warp_was_near:
        final_pos = _read_player_position_cerabot()
        if not final_pos:
            print("🌀 DIRECT: Warp teleport assumed (position unavailable immediately after warp)")
            return True
        final_distance = abs(final_pos[0] - target_pos[0]) + abs(final_pos[1] - target_pos[1])
        if final_distance >= teleport_distance_threshold:
            print("🌀 DIRECT: Warp teleport detected after direct movement attempts")
            return True
    
    print(f"❌ DIRECT: Failed to reach target after {max_attempts} attempts")
    return False

def _get_direction_to_target(current_pos, target_pos):
    """Calculate direction key for single-step movement"""
    try:
        x_diff = target_pos[0] - current_pos[0]
        y_diff = target_pos[1] - current_pos[1]
        
        # Only allow single-step movements
        if abs(x_diff) + abs(y_diff) != 1:
            return None
        
        direction_map = {
            (1, 0): "right",
            (-1, 0): "left", 
            (0, 1): "down",
            (0, -1): "up"
        }
        
        return direction_map.get((x_diff, y_diff), None)
    except Exception as e:
        print(f"❌ Direction calculation error: {e}")
        return None

def _perform_movement_step(direction: str, fast_mode: bool):
    """Execute a single movement step with configurable timing."""
    global last_direction
    import time
    import pydirectinput

    if fast_mode:
        try:
            pydirectinput.keyDown(direction)
            time.sleep(0.2)
        finally:
            try:
                pydirectinput.keyUp(direction)
            except Exception:
                pass
        time.sleep(0.05)
        last_direction = direction
    else:
        if direction != last_direction:
            press_key(direction, presses=2, delay=0.05)
        else:
            press_key(direction, presses=1, delay=0.05)
        last_direction = direction

_DIRECTION_VECTORS = {
    "up": (0, -1),
    "right": (1, 0),
    "down": (0, 1),
    "left": (-1, 0),
}

_CLICK_DIRECTION_INDEX = {"up": 0, "right": 1, "down": 2, "left": 3}


def _direction_to_vector(direction: str):
    """Return (dx, dy) for a facing direction name."""
    if not direction:
        return None
    return _DIRECTION_VECTORS.get(direction.lower())


def _get_directional_click_point(direction: str):
    """Return the configured click point for the given facing direction, if available."""
    if not direction:
        return None
    idx = _CLICK_DIRECTION_INDEX.get(direction.lower())
    if idx is None:
        return None
    if idx < len(resurrect_points):
        point = resurrect_points[idx]
        if point and len(point) >= 2:
            return (int(point[0]), int(point[1]))
    return None


def _generate_task_approaches(task, preferred_direction=None):
    """Produce ordered approach options (position, direction) around the task's target tile."""
    base_direction = (task.get("Direction") or "down").lower()
    base_vec = _direction_to_vector(base_direction) or (0, 1)
    x = int(task.get("X", 0))
    y = int(task.get("Y", 0))
    target_tile = (x + base_vec[0], y + base_vec[1])

    all_dirs = ["up", "right", "down", "left"]
    ordered_dirs = []

    if preferred_direction and preferred_direction in all_dirs:
        ordered_dirs.append(preferred_direction)
    if base_direction in all_dirs and base_direction not in ordered_dirs:
        ordered_dirs.append(base_direction)
    for d in all_dirs:
        if d not in ordered_dirs:
            ordered_dirs.append(d)

    approaches = []
    seen_positions = set()
    for dir_name in ordered_dirs:
        vec = _direction_to_vector(dir_name)
        if not vec:
            continue
        approach_pos = (target_tile[0] - vec[0], target_tile[1] - vec[1])
        if approach_pos in seen_positions:
            continue
        seen_positions.add(approach_pos)
        approaches.append(
            {
                "position": approach_pos,
                "direction": dir_name,
                "target": target_tile,
                "is_primary": dir_name == base_direction,
            }
        )
    return approaches


def _attempt_task_navigation_with_alternatives(task, walkable_tiles, task_key=None):
    """
    Try to reach the best available tile for executing the task.
    Returns (success, arrival_pos, facing_direction, target_tile).
    """
    action = task.get("Action", "")
    x = int(task.get("X", 0))
    y = int(task.get("Y", 0))
    default_direction = (task.get("Direction") or "down").lower()

    if action not in {"Ctrl", "Click", "DoubleClick", "RightClick"}:
        success = _navigate_to_position_cerabot(
            x, y, walkable_tiles, warp_mode=(action == "Warp")
        )
        if success:
            return True, (x, y), default_direction, None
        return False, None, default_direction, None

    preferred_direction = None
    if task_key is not None:
        preferred_direction = _task_last_success_direction.get(task_key)

    approaches = _generate_task_approaches(task, preferred_direction=preferred_direction)
    if not approaches:
        success = _navigate_to_position_cerabot(x, y, walkable_tiles)
        if success:
            return True, (x, y), default_direction, None
        return False, None, default_direction, None

    for idx, approach in enumerate(approaches):
        pos = approach["position"]
        direction = approach["direction"]
        if idx > 0:
            print(f"[TASK] Trying alternate approach at {pos} facing {direction}")
        success = _navigate_to_position_cerabot(pos[0], pos[1], walkable_tiles)
        if success:
            if task_key is not None:
                _task_last_success_direction[task_key] = direction
            return True, pos, direction, approach["target"]

    return False, None, default_direction, approaches[0]["target"]

def _clean_expired_blocked_tiles():
    """Remove expired temporary blocked tiles"""
    global _task_temporary_blocked_tiles
    import time
    current_time = time.time()
    expired = [tile for tile, exp_time in _task_temporary_blocked_tiles.items() if exp_time <= current_time]
    for tile in expired:
        _task_temporary_blocked_tiles.pop(tile, None)

def _mark_tile_blocked(tile, permanent=False):
    """Mark a tile as blocked (temporary or permanent)"""
    global _task_temporary_blocked_tiles, _task_permanent_blocked_tiles
    import time
    if permanent:
        _task_permanent_blocked_tiles.add(tile)
        print(f"🚧 Marked {tile} as permanently blocked")
    else:
        # Temporary block expires in 5 minutes
        expire_time = time.time() + 300
        _task_temporary_blocked_tiles[tile] = expire_time
        print(f"🚧 Marked {tile} as temporarily blocked (expires in 5 min)")

def _try_force_movement_cerabot(target_pos, timeout=None):
    """Try to force movement toward target by holding direction key for specified duration - matches npc4"""
    import time
    import pydirectinput
    
    if timeout is None:
        timeout = float(FORCE_MOVEMENT_SECONDS)
    
    current_pos = _read_player_position_cerabot()
    if not current_pos:
        return False
    
    # Calculate direction for force movement
    x_diff = target_pos[0] - current_pos[0]
    y_diff = target_pos[1] - current_pos[1]
    
    direction = None
    if abs(x_diff) >= abs(y_diff):
        if x_diff > 0:
            direction = "right"
        elif x_diff < 0:
            direction = "left"
    else:
        if y_diff > 0:
            direction = "down"
        elif y_diff < 0:
            direction = "up"
    
    if not direction:
        return False
    
    print(f"🔥 Force movement: Holding {direction.upper()} for {timeout} seconds")
    
    try:
        # Switch to game window
        try:
            windows = pyautogui.getWindowsWithTitle("Endless")
            if windows:
                windows[0].activate()
                time.sleep(0.5)
        except:
            pass
        
        pydirectinput.keyDown(direction)
        start_time = time.time()
        initial_pos = current_pos
        
        # Monitor movement during hold (matches npc4)
        while time.time() - start_time < timeout:
            if TASK_CANCEL.is_set():
                break
            time.sleep(0.1)
            current_check_pos = _read_player_position_cerabot()
            
            if current_check_pos and current_check_pos != initial_pos:
                pydirectinput.keyUp(direction)
                print(f"✅ Movement detected during force hold, position changed to {current_check_pos}")
                return current_check_pos == target_pos
        
        pydirectinput.keyUp(direction)
        
    except Exception as e:
        print(f"❌ Force movement error: {e}")
        try:
            pydirectinput.keyUp(direction)  # Ensure key is released
        except:
            pass
        return False
    
    time.sleep(0.3)
    new_pos = _read_player_position_cerabot()
    if new_pos == target_pos:
        print("✅ Force movement successful - reached target!")
        return True
    
    print(f"❌ Force movement failed - still at {new_pos}")
    return False

def _handle_movement_obstacle_cerabot(current_pos, next_pos, direction, attempt_number, walkable_tiles, final_target):
    """
    Multi-step obstacle handling - EXACT match to npc4's EnhancedObstacleHandler
    Returns: (success, action, result)
    - success: bool - whether obstacle was handled
    - action: str - "continue", "use_alternative_path", "recompute_path", "next_stage", "abort"
    - result: path or None
    """
    import time
    import pyautogui
    import pydirectinput
    
    print(f"🚫 OBSTACLE: Can't move {direction} from {current_pos} to {next_pos} (attempt {attempt_number}/6)")
    
    # STAGE 1: Mark as blocked and find alternative path (matches npc4's _stage2_mark_blocked_and_reroute)
    if attempt_number == 1:
        # Don't block the final target
        if next_pos == final_target:
            print(f"🚫 STAGE 1: NOT blocking {next_pos} - it's the FINAL TARGET, trying force movement")
            return False, "next_stage", None
        
        print(f"🚧 STAGE 1: Marking {next_pos} as temporarily blocked and finding alternative")
        # Mark the target tile as temporarily blocked (5 minute expiry) - matches npc4
        expire_time = time.time() + 300
        _task_temporary_blocked_tiles[next_pos] = expire_time
        
        # Find alternative path
        _clean_expired_blocked_tiles()
        current_time = time.time()
        active_blocked = {tile for tile, exp_time in _task_temporary_blocked_tiles.items() 
                         if exp_time > current_time and tile != final_target}
        permanent_blocked_filtered = _task_permanent_blocked_tiles - {final_target}
        modified_walkable = walkable_tiles - active_blocked - permanent_blocked_filtered
        if final_target not in modified_walkable:
            modified_walkable.add(final_target)
        
        allow_bias = final_target not in walkable_tiles
        alt_path = _astar_pathfinding_cerabot(current_pos, final_target, modified_walkable, allow_unwalkable_bias=allow_bias)
        if alt_path and len(alt_path) > 1:
            print(f"✅ STAGE 1 SUCCESS: Found alternative path with {len(alt_path)} steps")
            return True, "use_alternative_path", alt_path
        
        print(f"❌ STAGE 1 FAILED: No alternative path")
        return False, "recompute_path", "stage1_no_alternative_path"
    
    # STAGE 2: Force movement (matches npc4's _stage3_force_movement)
    elif attempt_number == 2:
        print(f"💪 STAGE 2: Clicking center screen + attempting force movement {direction}")
        try:
            # Click center of GAME WINDOW to close any dialogs/menus
            try:
                windows = pyautogui.getWindowsWithTitle("Endless")
                if windows:
                    win = windows[0]
                    center_x = win.left + win.width // 2
                    center_y = win.top + win.height // 2
                    print(f"🖱️ STAGE 2: Clicking center of game window ({center_x}, {center_y})")
                    pyautogui.click(center_x, center_y)
                    time.sleep(0.2)
            except Exception as e:
                print(f"⚠️ STAGE 2: Center click error: {e}")
            
            # Release CTRL if held
            try:
                release_key('ctrl')
            except:
                pass
            
            # Press F12 once before force movement if CTRL is not held
            try:
                if not keyboard.is_pressed('ctrl'):
                    pydirectinput.press('f12')
                    print("🔧 STAGE 2: F12 pressed before force movement (CTRL not held)")
                    time.sleep(0.1)
            except Exception as f12_err:
                print(f"⚠️ STAGE 2: F12 press error: {f12_err}")
            
            # Force movement using the configured duration
            force_duration = float(FORCE_MOVEMENT_SECONDS)
            success = _try_force_movement_cerabot(next_pos, force_duration)
            
            if success:
                print(f"✅ STAGE 2 SUCCESS: Force movement broke through obstacle")
                return True, "continue", "force_movement_succeeded"
            
            print(f"❌ STAGE 2 FAILED: Force movement didn't work")
            return False, "next_stage", "force_movement_failed"
        except Exception as e:
            print(f"❌ STAGE 2 ERROR: {e}")
            return False, "next_stage", None
    
    # STAGE 3: ESC recovery + try all directions (matches npc4's _stage4_stuck_recovery)
    elif attempt_number == 3:
        print(f"🚨 STAGE 3: Pressing ESC 4 times + clicking center + trying all directions with 3 taps each")
        try:
            # Release CTRL
            try:
                release_key('ctrl')
                # Force physical release
                try:
                    pydirectinput.keyUp('ctrl')
                except:
                    pass
                time.sleep(0.2)  # Wait for CTRL to release
            except:
                pass
            
            # Press ESC 4 times to clear any menus/dialogs
            for i in range(4):
                print(f"⌨️ Pressing ESC ({i+1}/4)")
                try:
                    pydirectinput.press('esc')
                    time.sleep(0.1)
                except:
                    pass
            
            # Click center of GAME WINDOW to close any dialogs/menus
            try:
                windows = pyautogui.getWindowsWithTitle("Endless")
                if windows:
                    win = windows[0]
                    center_x = win.left + win.width // 2
                    center_y = win.top + win.height // 2
                    print(f"🖱️ STAGE 3: Clicking center of game window ({center_x}, {center_y})")
                    pyautogui.click(center_x, center_y)
                    time.sleep(0.2)
            except Exception as e:
                print(f"⚠️ STAGE 3: Center click error: {e}")
            
            # Give time for ESC presses to take effect
            time.sleep(0.3)
            
            # Check if position changed after ESC presses
            new_pos = _read_player_position_cerabot()
            if new_pos and new_pos != current_pos:
                print(f"✅ STAGE 3 SUCCESS: ESC/click freed the player to {new_pos}")
                return True, "recompute_path", "esc_freed_player"
            
            print(f"⚠️ STAGE 3: ESC/click didn't work, trying ALL directions with 3 taps each...")
            
            # Try all 4 directions to get unstuck
            directions = ['up', 'down', 'left', 'right']
            
            for dir_key in directions:
                print(f"🔄 STAGE 3: Trying {dir_key} (3 taps)...")
                
                # Get position before trying this direction
                before_pos = _read_player_position_cerabot()
                if not before_pos:
                    before_pos = current_pos
                
                # Tap this direction 3 times
                for tap in range(3):
                    try:
                        pydirectinput.keyDown(dir_key)
                        time.sleep(0.03)  # 30ms tap (matches npc4)
                        pydirectinput.keyUp(dir_key)
                        time.sleep(0.05)
                    except Exception as press_error:
                        print(f"⚠️ STAGE 3: Key press error on tap {tap+1}: {press_error}")
                
                time.sleep(0.1)
                
                # Check if we moved AT ALL in this direction
                after_pos = _read_player_position_cerabot()
                if after_pos and after_pos != before_pos:
                    print(f"✅ STAGE 3 SUCCESS: Moved {dir_key}! {before_pos} → {after_pos}")
                    return True, "recompute_path", f"unstuck_by_{dir_key}"
                else:
                    print(f"❌ {dir_key}: No movement detected")
            
            print(f"❌ STAGE 3 FAILED: All 4 directions blocked after 3 taps each")
            return False, "next_stage", "all_directions_stuck"
            
        except Exception as e:
            print(f"❌ STAGE 3 ERROR: {e}")
            return False, "next_stage", "stuck_recovery_error"
    
    # STAGE 4: Emergency retry - try alternate directions (matches npc4's _stage5_emergency_retry)
    elif attempt_number == 4:
        print(f"🔄 STAGE 4: Trying alternate directions to reach {next_pos}")
        
        # Temporarily mark this target as problematic
        _task_temporary_blocked_tiles[next_pos] = time.time() + 30  # 30s block
        
        # Direction deltas
        deltas = {
            'up':    (0, -1),
            'down':  (0,  1),
            'left':  (-1, 0),
            'right': (1,  0),
        }
        
        # Try ALL directions (including original - situation may have changed)
        for dir_key, (dx, dy) in deltas.items():
            alt_pos = (current_pos[0] + dx, current_pos[1] + dy)
            if alt_pos not in walkable_tiles:
                print(f"🚫 STAGE 4: {dir_key} → {alt_pos} not walkable")
                continue
            
            print(f"🔄 STAGE 4: Attempting force-move {dir_key} → {alt_pos}")
            # Use force movement with the configured duration
            success = _try_force_movement_cerabot(alt_pos, float(FORCE_MOVEMENT_SECONDS))
            if success:
                print(f"✅ STAGE 4 SUCCESS: Moved {dir_key} to {alt_pos}!")
                return True, "continue", "force_moved_alternate_direction"
        
        # None of the directions worked — move to Stage 5 for retreat and wide avoidance
        print(f"❌ STAGE 4 FAILED: All 4 directions blocked")
        return False, "next_stage", "all_directions_blocked"
    
    # STAGE 5: Retreat and wide avoidance (matches npc4's _stage6_retreat_and_wide_avoidance)
    elif attempt_number == 5:
        print(f"🔙 STAGE 5: RETREAT AND WIDE AVOIDANCE - Last resort!")
        
        # Mark a WIDE exclusion zone around the blocked tile (5x5 grid) - matches npc4
        print(f"🚫 STAGE 5: Marking 5x5 exclusion zone around {next_pos} for 5 minutes")
        expire_time = time.time() + 300  # 5 minutes
        bx, by = next_pos
        
        for dx in range(-2, 3):  # -2 to +2 = 5 tiles wide
            for dy in range(-2, 3):  # -2 to +2 = 5 tiles wide
                exclude_tile = (bx + dx, by + dy)
                _task_temporary_blocked_tiles[exclude_tile] = expire_time
        
        print(f"🚫 STAGE 5: Marked exclusion zone tiles as blocked")
        
        # Try to retreat back 2-3 tiles
        print(f"🔙 STAGE 5: Attempting to retreat back from {current_pos}")
        
        # Calculate retreat direction (opposite of current heading toward target)
        dx_to_target = final_target[0] - current_pos[0]
        dy_to_target = final_target[1] - current_pos[1]
        
        # Retreat in opposite direction
        retreat_direction = None
        if abs(dx_to_target) > abs(dy_to_target):
            # Moving primarily horizontally, retreat vertically or backward
            retreat_direction = 'left' if dx_to_target > 0 else 'right'
        else:
            # Moving primarily vertically, retreat horizontally or backward
            retreat_direction = 'up' if dy_to_target > 0 else 'down'
        
        print(f"🔙 STAGE 5: Retreating {retreat_direction} for 2-3 tiles")
        
        # Execute retreat movement (try to retreat 3 tiles)
        retreat_success = False
        current_retreat_pos = current_pos
        for i in range(3):  # Try to retreat 3 tiles
            try:
                # Switch to game window
                try:
                    windows = pyautogui.getWindowsWithTitle("Endless")
                    if windows:
                        windows[0].activate()
                except:
                    pass
                
                pydirectinput.keyDown(retreat_direction)
                time.sleep(0.5)   # Normal hold for task navigation (matches npc4)
                pydirectinput.keyUp(retreat_direction)
                time.sleep(0.2)
                
                # Check if we moved
                new_pos = _read_player_position_cerabot()
                if new_pos and new_pos != current_retreat_pos:
                    print(f"✅ STAGE 5: Retreated to {new_pos} (step {i+1}/3)")
                    current_retreat_pos = new_pos
                    retreat_success = True
                else:
                    print(f"⚠️ STAGE 5: Retreat step {i+1} blocked")
                    break
            except Exception as e:
                print(f"❌ STAGE 5: Retreat error: {e}")
                break
        
        if not retreat_success:
            print(f"❌ STAGE 5: Could not retreat - navigation completely blocked")
            # Clear the exclusion zone since we can't retreat
            for dx in range(-2, 3):
                for dy in range(-2, 3):
                    exclude_tile = (bx + dx, by + dy)
                    _task_temporary_blocked_tiles.pop(exclude_tile, None)
            return False, "abort", "cannot_retreat"
        
        # Now find a new path with the wide exclusion zone
        print(f"🔄 STAGE 5: Finding new path from {current_retreat_pos} to {final_target} avoiding exclusion zone")
        
        # Create modified walkable tiles excluding the wide blocked area
        _clean_expired_blocked_tiles()
        current_time = time.time()
        active_blocked = {tile for tile, exp_time in _task_temporary_blocked_tiles.items() 
                         if exp_time > current_time}
        permanent_blocked = _task_permanent_blocked_tiles
        modified_walkable = walkable_tiles - active_blocked - permanent_blocked
        
        print(f"🗺️ STAGE 5: Pathfinding with {len(modified_walkable)} walkable tiles ({len(active_blocked)} temp blocked, {len(permanent_blocked)} permanent blocked)")
        
        # Try to find alternative path
        allow_bias = final_target not in walkable_tiles
        alternative_path = _astar_pathfinding_cerabot(current_retreat_pos, final_target, modified_walkable, allow_unwalkable_bias=allow_bias)
        
        if alternative_path and len(alternative_path) > 1:
            print(f"✅ STAGE 5 SUCCESS: Found new path with wide avoidance ({len(alternative_path)} steps)")
            return True, "use_alternative_path", alternative_path
        else:
            print(f"❌ STAGE 5 FAILED: No path available even with wide avoidance")
            # Clear the exclusion zone since we can't find a path at all
            for dx in range(-2, 3):
                for dy in range(-2, 3):
                    exclude_tile = (bx + dx, by + dy)
                    _task_temporary_blocked_tiles.pop(exclude_tile, None)
            print(f"🗑️ STAGE 5: Cleared exclusion zone - path completely blocked")
            return False, "abort", "no_path_available"
    
    # STAGE 6: Final - abort
    else:
        print(f"❌ STAGE 6: All obstacle handling stages failed - aborting")
        return False, "abort", None

def _navigate_to_position_cerabot(target_x, target_y, walkable_tiles, max_steps=500, warp_mode=False):
    """Navigate to target position using A* pathfinding with multi-step obstacle avoidance - adapted from npc4"""
    global _task_current_navigation_target, last_direction
    target_pos = (int(target_x), int(target_y))
    _task_current_navigation_target = target_pos  # Track final target for obstacle handling
    
    # Clean expired blocked tiles
    _clean_expired_blocked_tiles()
    
    current_pos = _read_player_position_cerabot()
    if not current_pos:
        print("❌ NAVIGATION: Cannot read current position")
        return False
    
    if current_pos == target_pos:
        print("✅ Already at target position")
        return True
    
    near_distance_threshold = 2
    teleport_distance_threshold = 8
    warp_recently_near = False
    warp_steps_since_near = 0
    warp_was_near = False
    
    # Remove blocked tiles from walkable set (but always allow the target itself)
    import time
    current_time = time.time()
    active_blocked = {tile for tile, exp_time in _task_temporary_blocked_tiles.items() 
                     if exp_time > current_time and tile != target_pos}
    permanent_blocked_filtered = _task_permanent_blocked_tiles - {target_pos}
    modified_walkable = walkable_tiles - active_blocked - permanent_blocked_filtered
    
    # Always allow current position (we're already there) and target position
    modified_walkable.add(current_pos)
    modified_walkable.add(target_pos)
    
    # Find path using modified walkable tiles
    path = _astar_pathfinding_cerabot(current_pos, target_pos, modified_walkable, allow_unwalkable_bias=warp_mode)
    if not path or len(path) < 2:
        print(f"⚠️ NAVIGATION: No valid path found to {target_pos}, attempting direct movement")
        # Fallback: Try direct movement toward goal using arrow keys
        return _try_direct_movement_to_target_cerabot(current_pos, target_pos, max_attempts=50, warp_mode=warp_mode)
    
    print(f"🎯 NAVIGATION: {len(path)} steps to target")
    
    # Execute path with multi-step obstacle handling
    path_index = 1  # Start from index 1 (skip current position at index 0)
    final_target_block_count = 0
    
    while path_index < len(path):
        if TASK_CANCEL.is_set() or not TASK_MODE:
            print("⏹️ NAVIGATION: Cancelled during path execution")
            return False
        
        if path_index > max_steps:
            print(f"❌ NAVIGATION: Max steps reached")
            return False
        
        # Refresh current position
        current_pos = _read_player_position_cerabot()
        if not current_pos:
            print("❌ NAVIGATION: Lost position during navigation")
            return False
        
        distance_to_target = abs(current_pos[0] - target_pos[0]) + abs(current_pos[1] - target_pos[1])
        if warp_mode:
            if distance_to_target <= near_distance_threshold:
                warp_recently_near = True
                warp_was_near = True
                warp_steps_since_near = 0
            elif warp_recently_near:
                warp_steps_since_near += 1
                if warp_steps_since_near > 4:
                    warp_recently_near = False
        
        # Check if reached target
        if current_pos == target_pos:
            print("✅ NAVIGATION: Reached target")
            return True
        
        # Get next step
        next_pos = path[path_index]
        
        # Get direction for this step
        direction = _get_direction_to_target(current_pos, next_pos)
        if not direction:
            print(f"❌ NAVIGATION: Cannot determine direction for step {path_index}")
            path_index += 1
            continue
        
        # Try movement with multi-step obstacle handling
        attempt = 1
        max_attempts = 6
        movement_success = False
        path_was_changed = False
        
        while attempt <= max_attempts and not movement_success:
            # Try the movement
            try:
                fast_movement = distance_to_target > 3
                _perform_movement_step(direction, fast_movement)
                
                # Verify movement
                time.sleep(0.05 if fast_movement else 0.15)
                new_pos = _read_player_position_cerabot()
                
                if warp_mode and warp_recently_near and new_pos:
                    new_distance = abs(new_pos[0] - target_pos[0]) + abs(new_pos[1] - target_pos[1])
                    if new_distance >= teleport_distance_threshold:
                        print("🌀 NAVIGATION: Detected warp teleport during movement")
                        return True
                
                if new_pos == next_pos:
                    # Movement succeeded
                    movement_success = True
                    break
                elif new_pos == current_pos:
                    # Movement failed - use obstacle handler
                    print(f"⚠️ NAVIGATION: Movement failed on step {path_index} to {next_pos} (attempt {attempt})")
                    
                    success, action, result = _handle_movement_obstacle_cerabot(
                        current_pos, next_pos, direction, attempt, walkable_tiles, target_pos
                    )
                    
                    if action == "continue":
                        # Try again
                        attempt += 1
                        continue
                    elif action == "use_alternative_path":
                        if result and len(result) > 1:
                            path = result
                            path_index = 0  # Will be incremented to 1 below
                            path_was_changed = True
                            print(f"🔄 NAVIGATION: Using alternative path with {len(path)} steps")
                            break
                        else:
                            attempt += 1
                            continue
                    elif action == "recompute_path":
                        # Recompute from current position
                        current_pos = _read_player_position_cerabot()
                        if current_pos:
                            _clean_expired_blocked_tiles()
                            current_time = time.time()
                            active_blocked = {tile for tile, exp_time in _task_temporary_blocked_tiles.items() 
                                             if exp_time > current_time and tile != target_pos}
                            permanent_blocked_filtered = _task_permanent_blocked_tiles - {target_pos}
                            modified_walkable = walkable_tiles - active_blocked - permanent_blocked_filtered
                            if target_pos not in modified_walkable:
                                modified_walkable.add(target_pos)
                            
                            new_path = _astar_pathfinding_cerabot(current_pos, target_pos, modified_walkable, allow_unwalkable_bias=warp_mode)
                            if new_path and len(new_path) > 1:
                                path = new_path
                                path_index = 0
                                path_was_changed = True
                                print(f"🔄 NAVIGATION: Recomputed path with {len(path)} steps")
                                break
                        attempt += 1
                        continue
                    elif action == "next_stage":
                        if next_pos == target_pos:
                            final_target_block_count += 1
                            if final_target_block_count > 1:
                                print("🚫 NAVIGATION: Final tile still blocked after force attempts; switching approach")
                                return False
                        attempt += 1
                        continue
                    elif action == "abort":
                        print(f"❌ NAVIGATION: Aborted by obstacle handler")
                        return False
                    else:
                        attempt += 1
                        continue
                elif new_pos is None:
                    if warp_mode and warp_recently_near:
                        print("🌀 NAVIGATION: Warp teleport suspected (position temporarily unavailable after move)")
                        return True
                    print(f"⚠️ NAVIGATION: Position unavailable after attempting move to {next_pos}")
                    attempt += 1
                    continue
                else:
                    # Moved but not to expected position - might have overshot or taken different path
                    print(f"⚠️ NAVIGATION: Moved to {new_pos} instead of {next_pos}, recomputing path...")
                    if warp_mode and warp_recently_near and new_pos:
                        new_distance = abs(new_pos[0] - target_pos[0]) + abs(new_pos[1] - target_pos[1])
                        if new_distance >= teleport_distance_threshold:
                            print("🌀 NAVIGATION: Detected warp teleport after unexpected move")
                            return True
                    # Recompute path from new position
                    _clean_expired_blocked_tiles()
                    current_time = time.time()
                    active_blocked = {tile for tile, exp_time in _task_temporary_blocked_tiles.items() 
                                     if exp_time > current_time and tile != target_pos}
                    permanent_blocked_filtered = _task_permanent_blocked_tiles - {target_pos}
                    modified_walkable = walkable_tiles - active_blocked - permanent_blocked_filtered
                    if target_pos not in modified_walkable:
                        modified_walkable.add(target_pos)
                    
                    new_path = _astar_pathfinding_cerabot(new_pos, target_pos, modified_walkable, allow_unwalkable_bias=warp_mode)
                    if new_path and len(new_path) > 1:
                        path = new_path
                        path_index = 0
                        path_was_changed = True
                        print(f"🔄 NAVIGATION: Recomputed path from {new_pos} with {len(path)} steps")
                        break
                    else:
                        attempt += 1
                        continue
                        
            except Exception as e:
                print(f"❌ NAVIGATION: Movement error on step {path_index}: {e}")
                attempt += 1
                continue
        
        if not movement_success and not path_was_changed:
            print(f"❌ NAVIGATION: Failed to move after {max_attempts} attempts")
            return False
        
        # Increment path index (or reset if path changed)
        if path_was_changed:
            path_index = 1  # Start from index 1 for new path
        else:
            path_index += 1
    
    # Final check
    final_pos = _read_player_position_cerabot()
    if warp_mode and warp_was_near:
        if not final_pos:
            print("🌀 NAVIGATION: Warp teleport assumed (position unavailable immediately after warp)")
            return True
        final_distance = abs(final_pos[0] - target_pos[0]) + abs(final_pos[1] - target_pos[1])
        if final_distance >= teleport_distance_threshold:
            print("🌀 NAVIGATION: Warp teleport detected after path execution")
            return True
    if final_pos == target_pos:
        print("✅ NAVIGATION: Successfully reached target")
        return True
    
    print(f"⚠️ NAVIGATION: Reached end of path but not at target (at {final_pos}, wanted {target_pos})")
    return False

def _pick_stand_tile_for_node(*args):
    """
    Accepts EITHER:
      (node_xy: (x,y), walkable: set[(x,y)], from_xy: (x,y))
    OR:
      (tx:int, ty:int, px:int|None, py:int|None)  -> walkable auto-loaded
    Returns a walkable neighbor of node_xy that's reachable from from_xy,
    preferring the one with the shortest A* path (then Manhattan distance).
    """
    # --- normalize arguments ---
    if len(args) == 3:
        node_xy, walkable, from_xy = args
        tx, ty = int(node_xy[0]), int(node_xy[1])
        px, py = int(from_xy[0]), int(from_xy[1])
        walkable = set(walkable)
    elif len(args) == 4:
        tx, ty, px, py = args
        tx, ty = int(tx), int(ty)
        # live XY if px/py not provided
        if px is None or py is None:
            lx, ly = _get_xy_safe()
            if lx is not None and ly is not None:
                px, py = int(lx), int(ly)
            else:
                d = player_data_manager.get_data()
                px = int(d.get("x", 0) or 0)
                py = int(d.get("y", 0) or 0)
        else:
            px, py = int(px), int(py)
        walkable = _load_walkable_tiles_as_set()
    else:
        raise TypeError("_pick_stand_tile_for_node expected 3 or 4 args")

    node_xy = (tx, ty)
    from_xy = (px, py)

    # --- candidate neighbors (Up, Right, Down, Left) ---
    x, y = node_xy
    candidates = [(x, y-1), (x+1, y), (x, y+1), (x-1, y)]
    candidates = [c for c in candidates if c in walkable]
    if not candidates:
        return None

    # prefer actually-reachable side (shortest A* path), tie-break by Manhattan
    def _score(c):
        p = astar_pathfinding(from_xy, c, walkable)
        return (len(p) if p else 10**9, abs(from_xy[0]-c[0]) + abs(from_xy[1]-c[1]))

    return min(candidates, key=_score)

def _harvest_once(node):
    tx, ty = node["x"], node["y"]
    kind   = node["type"]
    hold   = float(node.get("hold", 6.0 if kind in ("mine","chop") else globals().get("LOOT_HOLD_SECONDS", 2.5)))

    # 1) Decide where to stand (adjacent & walkable)
    px, py = _get_xy_safe()
    stand = _pick_stand_tile_for_node(tx, ty, px, py)
    if not stand:
        print(f"[HARVEST] No walkable adjacent tile for node ({tx},{ty}); skipping.")
        return
    sx, sy = stand

    # 2+4) Travel AND commit action via the unified target navigator
    class HarvestTarget:
        def get_xy(self):
            # We stand ON the chosen adjacent tile (not on the resource tile)
            return (sx, sy)

        def is_valid(self):
            # If you have a "node still present?" signal, call it here.
            # Otherwise we treat the node as valid until the action fails.
            return True

        def on_arrival(self):
            # Compute facing from *current live* XY toward node to avoid drift.
            cx, cy = _get_xy_safe()
            if cx is None or cy is None:
                return False
            facing = _desired_facing_for_tile(int(cx), int(cy), tx, ty, node.get("facing"))

            # Gate movement + perform your existing harvest action
            try:
                clicks_in_progress.set()
                long_hold = (kind in ("mine","chop")) or (float(hold) >= 1.2)
                if long_hold:
                    _pause_movement()  # safety for real holds
                _harvest_action(kind, facing, hold)
                return True
            finally:
                if long_hold:
                    _resume_movement()
                clicks_in_progress.clear()


    # Drive everything through the live-XY navigator (same contract as combat)
    go_to_target(HarvestTarget(), tag="HARVEST", near_thresh=0.6, timeout_s=40.0)


# ═══════════════════════════════════════════════════════════════
# TASK MODE: Task execution functions (from npc4, adapted for CeraBot)
# ═══════════════════════════════════════════════════════════════

def _face_direction_cerabot(direction_str):
    """Face a specific direction using CeraBot's system"""
    direction_map = {"down": 0, "left": 1, "up": 2, "right": 3}
    target_dir = direction_map.get(direction_str.lower(), 0)
    
    current_dir = _read_player_direction_cerabot()
    if current_dir is None:
        return False
    
    if current_dir == target_dir:
        return True
    
    # Get direction key
    dir_key = None
    if target_dir == 0:  # Down
        dir_key = "down"
    elif target_dir == 1:  # Left
        dir_key = "left"
    elif target_dir == 2:  # Up
        dir_key = "up"
    elif target_dir == 3:  # Right
        dir_key = "right"
    
    if dir_key:
        try:
            press_key(dir_key, presses=1, delay=0.1)
            time.sleep(0.05)
            return True
        except Exception as e:
            print(f"❌ Error facing direction: {e}")
            return False
    return False

def _switch_to_game_window():
    """Switch to game window - matches npc4's scanner.switch_to_game_window()"""
    try:
        windows = pyautogui.getWindowsWithTitle("Endless")
        if windows:
            windows[0].activate()
            return True
    except Exception:
        pass
    return False

def _execute_task_action_cerabot(task, task_id, direction_override=None, click_override=None):
    """Execute a task action - EXACT match to npc4's execute_task_action (with overrides)"""
    try:
        if TASK_CANCEL.is_set() or not TASK_MODE:
            print(f"⏹️ Task #{task_id} action cancelled")
            return
        action = task.get("Action", "")
        print(f"🎬 Executing Task #{task_id} action: {action}")
        
        # Handle Warp action (navigation handles this, but log it)
        if action == "Warp":
            print(f"🌀 Task #{task_id} Warp action (navigation handles this)")
            return
        
        if action == "Ctrl":
            direction = (direction_override or task.get("Direction", "down"))
            _face_direction_cerabot(direction)
            try:
                # Use pydirectinput for CTRL (matches CeraBot's approach and works reliably)
                _switch_to_game_window()
                pydirectinput.keyDown("ctrl")
                time.sleep(2.8)
                pydirectinput.keyUp("ctrl")
                print(f"✅ Task #{task_id} Ctrl action completed")
            except Exception as e:
                print(f"❌ Task #{task_id} Ctrl action error: {e}")
        
        elif action in ["Click", "DoubleClick", "RightClick"]:
            time.sleep(1.0)
            _switch_to_game_window()
            if click_override is not None and len(click_override) >= 2:
                x_click, y_click = click_override[0], click_override[1]
            else:
                click_coords = task.get("Click", (0, 0))
                # Handle both list and tuple formats
                if isinstance(click_coords, list) and len(click_coords) >= 2:
                    x_click, y_click = click_coords[0], click_coords[1]
                elif isinstance(click_coords, tuple) and len(click_coords) >= 2:
                    x_click, y_click = click_coords[0], click_coords[1]
                else:
                    # Attempt to derive from facing override if available
                    direction = direction_override or task.get("Direction", "down")
                    derived_click = _get_directional_click_point(direction)
                    if derived_click:
                        x_click, y_click = derived_click
                    else:
                        x_click, y_click = 0, 0
            
            if x_click == 0 and y_click == 0:
                print(f"⚠️ Task #{task_id} {action} has no click location set (0,0) - skipping click")
            else:
                try:
                    pydirectinput.moveTo(x_click, y_click)
                    if action == "Click":
                        pydirectinput.click()
                    elif action == "DoubleClick":
                        pydirectinput.click()
                        time.sleep(0.075)
                        pydirectinput.click()
                    elif action == "RightClick":
                        pydirectinput.rightClick()
                    if _sleep_with_cancel(2.5):
                        return
                    print(f"✅ Task #{task_id} {action} completed at ({x_click}, {y_click})")
                except Exception as e:
                    print(f"❌ Task #{task_id} {action} error: {e}")
        
        elif action in ["F1", "F2"]:
            # Disable F1 dash entirely; keep F2 - matches npc4
            if action == "F1":
                print(f"🚫 Task #{task_id} F1 dash disabled - skipping")
            else:
                direction = task.get("Direction", "down")
                _face_direction_cerabot(direction)
                _switch_to_game_window()
                time.sleep(0.5)
                key = action.lower()
                try:
                    pydirectinput.keyDown(key)
                    time.sleep(0.1)
                    pydirectinput.keyUp(key)
                    time.sleep(0.1)
                    print(f"✅ Task #{task_id} {action} key completed")
                except Exception as e:
                    print(f"❌ Task #{task_id} {action} key error: {e}")
        
        elif action == "Walk":
            print(f"🚶 Task #{task_id} executing Walk action - waiting 0.8 seconds")
            time.sleep(0.8)
            print(f"✅ Task #{task_id} Walk completed")
        
        elif action == "SIT":
            # Execute SIT action - matches npc4's execute_sit_action
            print(f"🪑 Task #{task_id} executing SIT action")
            try:
                _switch_to_game_window()
                if _sleep_with_cancel(0.5):
                    return
                pydirectinput.keyDown('f11')
                time.sleep(0.1)
                pydirectinput.keyUp('f11')
                print("🎮 Pressed F11 to start sitting")
                
                # Sit for configured duration
                sit_duration = SIT_TIMER_SECONDS
                start_sit_time = time.time()
                
                # Wait for sit duration (checking for cancellation)
                while time.time() - start_sit_time < sit_duration:
                    if TASK_CANCEL.is_set() or not TASK_MODE:
                        break
                    if _sleep_with_cancel(1.0):
                        return

                if TASK_MODE and not TASK_CANCEL.is_set():
                    _switch_to_game_window()
                    if _sleep_with_cancel(0.5):
                        return
                    pydirectinput.keyDown('f11')
                    time.sleep(0.1)
                    pydirectinput.keyUp('f11')
                    print("🎮 Pressed F11 to stop sitting")
                    if _sleep_with_cancel(5.0):
                        return
                # Click center of game window (matches npc4)
                try:
                    windows = pyautogui.getWindowsWithTitle("Endless")
                    if windows:
                        win = windows[0]
                        center_x = win.left + win.width // 2
                        center_y = win.top + win.height // 2
                        pyautogui.click(center_x, center_y)
                except Exception:
                    pass
                     
                print(f"✅ Task #{task_id} SIT completed")
            except Exception as e:
                print(f"❌ Task #{task_id} SIT error: {e}")
        
        else:
            print(f"⚠️ Task #{task_id} Unknown action: {action}")
            
    except Exception as e:
        print(f"❌ Task #{task_id} action execution error: {e}")

def _load_tasks():
    """Load tasks from saved_tasks directory - includes click coordinates"""
    global _tasks
    try:
        tasks_dir = "saved_tasks"
        if not os.path.exists(tasks_dir):
            os.makedirs(tasks_dir)
            return []
        
        # Look for task files (map_*.json format)
        task_files = [f for f in os.listdir(tasks_dir) if f.endswith('.json')]
        if not task_files:
            return []
        
        # Load first task file found (or use current map if available)
        task_file = os.path.join(tasks_dir, task_files[0])
        with open(task_file, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                loaded_tasks = data
            else:
                loaded_tasks = data.get('tasks', [])
        
        # Deserialize tasks with click coordinates
        _tasks = []
        for task_data in loaded_tasks:
            click_coords = task_data.get("Click", [0, 0])
            if isinstance(click_coords, list) and len(click_coords) >= 2:
                click_x, click_y = click_coords[0], click_coords[1]
            elif isinstance(click_coords, tuple) and len(click_coords) >= 2:
                click_x, click_y = click_coords[0], click_coords[1]
            else:
                click_x, click_y = 0, 0
            
            task = {
                "X": task_data.get("X", 0),
                "Y": task_data.get("Y", 0),
                "Action": task_data.get("Action", "Click"),
                "Direction": task_data.get("Direction", "down"),
                "Click": (click_x, click_y)
            }
            _tasks.append(task)
        
        print(f"📋 Loaded {len(_tasks)} tasks from {task_file}")
        return _tasks
    except Exception as e:
        print(f"❌ Error loading tasks: {e}")
        return []

def _save_tasks():
    """Save tasks to saved_tasks directory - includes click coordinates"""
    global _tasks
    try:
        tasks_dir = "saved_tasks"
        if not os.path.exists(tasks_dir):
            os.makedirs(tasks_dir)
        
        task_file = os.path.join(tasks_dir, "map_1.json")
        
        # Serialize tasks with click coordinates
        tasks_to_save = []
        for task in _tasks:
            click_coords = task.get("Click", (0, 0))
            if isinstance(click_coords, (list, tuple)) and len(click_coords) >= 2:
                click_x, click_y = click_coords[0], click_coords[1]
            else:
                click_x, click_y = 0, 0
            
            serialized_task = {
                "X": task.get("X", 0),
                "Y": task.get("Y", 0),
                "Action": task.get("Action", "Click"),
                "Direction": task.get("Direction", "down"),
                "Click": [click_x, click_y]
            }
            tasks_to_save.append(serialized_task)
        
        with open(task_file, 'w') as f:
            json.dump(tasks_to_save, f, indent=2)
        
        print(f"💾 Saved {len(_tasks)} tasks to {task_file}")
    except Exception as e:
        print(f"❌ Error saving tasks: {e}")

def _task_loop():
    """Main task execution loop - matches npc4's infinite retry system"""
    global TASK_MODE, _task_loops_remaining, _tasks
    import time
    
    print("[TASK] Task mode starting…")
    
    # Load tasks
    _tasks = _load_tasks()
    if not _tasks:
        print("[TASK] No tasks loaded; stopping.")
        return
    
    # Get walkable tiles for pathfinding
    walkable_tiles = _load_walkable_tiles_as_set()
    if not walkable_tiles:
        print("[TASK] No walkable tiles available; stopping.")
        return
    
    loop_count = 0
    while TASK_MODE and not TASK_CANCEL.is_set() and loop_count < _task_loops_remaining:
        loop_count += 1
        print(f"[TASK] Starting loop {loop_count}/{_task_loops_remaining}")
        
        for task_idx, task in enumerate(_tasks):
            if not TASK_MODE or TASK_CANCEL.is_set():
                break
            
            task_id = task_idx + 1
            x = int(task.get("X", 0))
            y = int(task.get("Y", 0))
            action = task.get("Action", "")
            
            # Validate task coordinates - skip invalid (0, 0) tasks
            if x == 0 and y == 0:
                print(f"⚠️ Task #{task_id} has invalid coordinates (0, 0) - skipping")
                continue
            
            print(f"[TASK] Loop {loop_count} - Task #{task_id}: Going to ({x}, {y}) for {action}")
            
            # INFINITE RETRY SYSTEM - matches npc4 (never skip tasks)
            success = False
            timed_out = False
            attempt_count = 0
            max_attempts = 50  # Safety limit to prevent infinite loops
            task_nav_start = time.time()
            
            while not success and attempt_count < max_attempts:
                if not TASK_MODE or TASK_CANCEL.is_set():
                    break
                
                if time.time() - task_nav_start > 120:
                    print(f"⏱️ Task #{task_id} Navigation exceeded 120s – skipping this task")
                    timed_out = True
                    break

                attempt_count += 1
                if attempt_count > 1:
                    print(f"[TASK] Task #{task_id} Retry attempt {attempt_count}/{max_attempts}")
                
                # Special handling for Warp tasks
                if action == "Warp":
                    # For warp tasks, navigate to warp tile and wait for activation
                    nav_success = _navigate_to_position_cerabot(x, y, walkable_tiles, warp_mode=True)
                    if nav_success:
                        # Wait at warp tile for activation
                        print(f"🌀 Task #{task_id} At warp tile, waiting for activation...")
                        if _sleep_with_cancel(1.0):
                            break
                    else:
                        print(f"❌ Task #{task_id} Failed to reach warp tile (attempt {attempt_count})")
                        if _sleep_with_cancel(1.0):
                            break
                        continue
                else:
                    # Normal task - navigate then execute action (with alternative approaches)
                    task_key = (x, y, action, task_idx)
                    nav_success, arrival_pos, effective_direction, target_tile = _attempt_task_navigation_with_alternatives(
                        task, walkable_tiles, task_key=task_key
                    )
                    
                    if nav_success:
                        # Verify we're actually at (or near) the arrival position before executing
                        final_pos = _read_player_position_cerabot()
                        if not final_pos:
                            print(f"⚠️ Task #{task_id} Cannot read position after navigation")
                            if _sleep_with_cancel(1.0):
                                break
                            continue

                        arrival_distance = (
                            abs(final_pos[0] - arrival_pos[0]) + abs(final_pos[1] - arrival_pos[1])
                            if arrival_pos else 0
                        )
                        target_distance = (
                            abs(final_pos[0] - target_tile[0]) + abs(final_pos[1] - target_tile[1])
                            if target_tile else arrival_distance
                        )

                        if arrival_distance <= 1 or target_distance <= 1:
                            print(f"✅ Task #{task_id} Reached execution position {final_pos}, facing {effective_direction}")
                            if action == "Combat":
                                if effective_direction:
                                    _face_direction_cerabot(effective_direction)
                                combat_success = _run_combat_task(
                                    task,
                                    task_id,
                                    int(COMBAT_TASK_DURATION),
                                )
                                if combat_success:
                                    success = True
                                else:
                                    if _sleep_with_cancel(1.0):
                                        break
                                    continue
                            else:
                                # Determine click override if we changed direction
                                click_override = None
                                if action in ["Click", "DoubleClick", "RightClick"]:
                                    click_override = _get_directional_click_point(effective_direction)
                                    if not click_override:
                                        click_coords = task.get("Click")
                                        if isinstance(click_coords, (list, tuple)) and len(click_coords) >= 2:
                                            click_override = (click_coords[0], click_coords[1])

                                # Execute task action (even if it errors, we consider navigation success)
                                try:
                                    _execute_task_action_cerabot(
                                        task,
                                        task_id,
                                        direction_override=effective_direction,
                                        click_override=click_override,
                                    )
                                except Exception as e:
                                    print(f"⚠️ Task #{task_id} Action execution error (but navigation succeeded): {e}")
                                # Mark as successful since we reached the location and attempted the action
                                success = True
                        else:
                            print(
                                f"⚠️ Task #{task_id} Navigation reported success but too far "
                                f"(at {final_pos}, wanted near {arrival_pos}, distance {arrival_distance})"
                            )
                            if _sleep_with_cancel(1.0):
                                break
                            continue
                    else:
                        print(f"❌ Task #{task_id} Navigation failed (attempt {attempt_count})")
                        if _sleep_with_cancel(1.0):
                            break
                        continue
                
                # If we got here, task completed successfully
                break
            
            if timed_out:
                print(f"⚠️ Task #{task_id} skipped after 2 minutes of navigation attempts")
                continue

            if not success:
                print(f"❌ Task #{task_id} Failed after {max_attempts} attempts - continuing to next task")
            else:
                print(f"✅ Task #{task_id} Completed successfully - moving to next task")
            
            if _sleep_with_cancel(0.5):
                break
        
        print(f"[TASK] Loop {loop_count} completed")
        time.sleep(1.0)
    
    print(f"[TASK] Task mode stopped after {loop_count} loops")

def _harvest_loop():
    import time, random
    print("[HARVEST] loop starting…")
    while HARVEST_MODE and not HARVEST_CANCEL.is_set():
        nodes = _load_harvest_nodes()  # reload so GUI edits apply live
        if not nodes:
            print("[HARVEST] No harvest nodes recorded for this map; stopping.")
            break
        for n in nodes:
            if not HARVEST_MODE:
                break
            print(f"[HARVEST] -> ({n['x']},{n['y']}) type={n['type']} face={n.get('facing','auto')} hold={n.get('hold')}")
            _harvest_once(n)
            _sleep_cancellable(random.uniform(0.04, 0.10))
    print("[HARVEST] loop stopped.")

def start_task_mode():
    """Start task mode - replaces harvest mode"""
    global TASK_MODE, _task_thread, _task_loops_remaining
    if TASK_MODE:
        print("[TASK] already running"); return False
    
    # Load tasks
    tasks = _load_tasks()
    if not tasks:
        print("[TASK] Refusing to enable: no tasks loaded.")
        return False
    
    # Check walkable tiles
    walkable = _load_walkable_tiles_as_set()
    if not walkable:
        print("[TASK] Refusing to enable: no walkable tiles available.")
        return False
    
    TASK_CANCEL.clear()
    stop_bot()  # pause combat threads while doing tasks
    TASK_MODE = True
    _task_thread = threading.Thread(target=_task_loop, daemon=True)
    _task_thread.start()
    print("[TASK] Task mode enabled.")
    return True

def stop_task_mode():
    """Stop task mode"""
    global TASK_MODE, _task_thread
    TASK_MODE = False
    TASK_CANCEL.set()
    try: release_key('ctrl')
    except Exception: pass
    try:
        if _task_thread and _task_thread.is_alive():
            import time
            timeout_at = time.time() + 5.0
            while _task_thread.is_alive() and time.time() < timeout_at:
                _task_thread.join(timeout=0.2)
            if _task_thread.is_alive():
                print("⚠️ [TASK] Task thread still running after stop request")
    except Exception as e:
        print(f"⚠️ [TASK] Error while stopping task thread: {e}")
    stop_bot()
    print("[TASK] Task mode disabled.")

def start_harvest_mode():
    global HARVEST_MODE, _harvest_thread
    if HARVEST_MODE:
        print("[HARVEST] already running"); return False
    if not _load_harvest_nodes():
        print("[HARVEST] Refusing to enable: no harvest nodes in walkable.json.")
        return False
    HARVEST_CANCEL.clear()           # NEW
    stop_bot()                       # pause combat threads while harvesting
    HARVEST_MODE = True
    _harvest_thread = threading.Thread(target=_harvest_loop, daemon=True)
    _harvest_thread.start()
    print("[HARVEST] enabled.")
    return True

def stop_harvest_mode():
    global HARVEST_MODE, _harvest_thread
    HARVEST_MODE = False
    HARVEST_CANCEL.set()          # ← add this
    try: release_key('ctrl')
    except Exception: pass
    try:
        if _harvest_thread and _harvest_thread.is_alive():
            _harvest_thread.join(timeout=1.5)
    except Exception:
        pass
    stop_bot()
    print("[HARVEST] disabled.")


def _resolve_walkable_path(preferred: str | None) -> Path | None:
    """
    Return the first existing path for the walkable JSON.
    Search order:
      1) Explicit CLI arg (file or directory)
      2) Env var WALKABLE_JSON
      3) Next to this script: <script_dir>/walkable.json
      4) Current working dir: <cwd>/walkable.json
      5) Fallback name variants: walkable, walkable.json.json in both locations
    """
    candidates: list[Path] = []

    def expand(p: str | Path) -> Path:
        return Path(os.path.expandvars(os.path.expanduser(str(p)))).resolve()

    # 1) CLI arg
    if preferred:
        p = expand(preferred)
        if p.is_dir():
            candidates.append(p / "walkable.json")
        else:
            candidates.append(p)

    # 2) ENV var
    env = os.getenv("WALKABLE_JSON")
    if env:
        q = expand(env)
        candidates.append(q if q.is_file() else q / "walkable.json")

    # 3) Script dir + 4) CWD
    script_dir = Path(__file__).resolve().parent
    cwd = Path.cwd()
    for base in (script_dir, cwd):
        candidates.append(base / "walkable.json")
        # common "double extension" and "no extension" mistakes:
        candidates.append(base / "walkable.json.json")
        candidates.append(base / "walkable")

    # Return the first that exists
    for c in candidates:
        try:
            if c.is_file():
                return c
        except Exception:
            pass

    return None  # not found

# ---------- walkable.json helpers (harvest) ----------
def load_walkable_json():
    """Load the same walkable.json your pathfinder uses."""
    p = _resolve_walkable_path(WALKABLE_ARG)
    if not p:
        raise FileNotFoundError("walkable.json not found (via _resolve_walkable_path)")
    import json
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "harvest_nodes" not in data or not isinstance(data["harvest_nodes"], list):
        data["harvest_nodes"] = []
    return data, p

def save_walkable_json(data, path_obj):
    """Persist walkable.json (pretty-printed)."""
    import json
    with open(path_obj, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[HARVEST] Saved walkable to {path_obj}")

def initialize_pymem():
    global pm
    if pm is None:
        pm = pymem.Pymem("Endless.exe")

def press_key(key, presses=2, delay=0.1):
    """
    Presses a key and optionally waits for a specified delay.
    """
    pydirectinput.press(key, presses)
    time.sleep(delay)

def hold_key(key):
    pydirectinput.keyDown(key)

def release_key(key):
    pydirectinput.keyUp(key)

def on_message_xy(message, data):
    global xstarted, x_address, y_address
    if message['type'] == 'send':
        addresses = message['payload']
        x_address = int(addresses['x_address'], 16)
        y_address = int(addresses['y_address'], 16)
        if debug == 1:
            print(f"X Address: {hex(x_address)}, Y Address: {hex(y_address)}")
        # Mark as completed and detach session
        xstarted = 1
        session.detach()
    else:
        print(f"Error: {message}")


def start_frida_exp():
    """
    Attach to EXP hook instruction and resolve stat_base immediately.
    """
    global stat_base, session
    import frida

    session = frida.attach("Endless.exe")
    script_code = f"""
    Interceptor.attach(ptr("0x{EXP_HOOK_ADDR:X}"), {{
        onEnter: function(args) {{
            var playerBase = this.context.ebx;
            var expAddr = playerBase.add(0x28); // EXP offset
            send({{exp_address: expAddr.toString()}});
        }}
    }});
    """
    script = session.create_script(script_code)
    script.on('message', on_message_exp)
    script.load()

    print("[frida] EXP hook installed, waiting for game to run...")
    # ❌ removed blocking while-loop


def start_frida_weight_lock(weight_write_offsets):
    """
    Hooks the instructions that write the weight value and forces the
    written register to 0 (locks weight at zero).

    Params:
        weight_write_offsets: iterable of relative offsets (RVA) from Endless.exe base
                              e.g. [0xFAF26, 0xFA5AF]
    """
    import frida, threading, time

    # Attach once for this feature (kept separate from your other sessions)
    session = frida.attach("Endless.exe")

    # Build the Frida script (module-safe, 32/64-bit friendly)
    js = f"""
    (function() {{
        var mod = null;
        try {{
            mod = Process.getModuleByName("Endless.exe");
        }} catch (e) {{
            var mods = Process.enumerateModules();
            mod = mods.length ? mods[0] : null;
        }}
        if (!mod) {{
            throw new Error("Could not resolve Endless.exe module.");
        }}
        var base = mod.base;

        // Offsets provided by Python
        var OFFS = [{", ".join("ptr(0x%X)" % off for off in weight_write_offsets)}];

        OFFS.forEach(function(rel) {{
            var addr = base.add(rel);
            try {{
                Interceptor.attach(addr, {{
                    onEnter: function (args) {{
                        // Force the destination register/value to zero.
                        // If this instruction writes from EAX/RAX (common pattern),
                        // zeroing it here will clamp the write to 0.
                        if (this.context.eax !== undefined) {{
                            this.context.eax = 0;
                        }} else if (this.context.rax !== undefined) {{
                            this.context.rax = ptr(0);
                        }}
                    }}
                }});
            }} catch (e) {{
                send({{type: "weight-lock-hook-error", address: addr.toString(), error: e.toString()}});
            }}
        }});

        send({{type: "weight-lock-ready", count: OFFS.length}});
    }})();
    """.strip()

    script = session.create_script(js)

    def _on_message(message, data):
        # Bubble up meaningful errors to your console
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "weight-lock-ready":
                print(f"[frida] Weight lock enabled on {{payload.get('count')}} addresses.")
            elif payload.get("type") == "weight-lock-hook-error":
                print(f"[frida] Hook failed @ {{payload.get('address')}}: {{payload.get('error')}}")
        elif message.get("type") == "error":
            print("[frida] Script error:", message)

    script.on("message", _on_message)
    script.load()
    print("[frida] Weight lock hooks installed (listening).")
    # Keep the session alive in this thread
    # (Your program stays alive anyway; no busy loop needed.)

def start_frida_session_xy(walk_address):
    # walk_address can be "0xEC16F" or an int-like; we pass it as a JS number safely
    global session
    session = frida.attach("Endless.exe")
    print("XY Started - Waiting for you to move to begin")

    script_code = f"""
    // safer: use Process.getModuleByName().base and guard nulls
    var mod = null;
    try {{
      mod = Process.getModuleByName("Endless.exe");
    }} catch (e) {{
      // fallback: pick main module
      var mods = Process.enumerateModules();
      mod = mods.length ? mods[0] : null;
    }}

    if (!mod) {{
      throw new Error("Could not find module base for Endless.exe");
    }}

    var base = mod.base;                      // NativePointer
    var rel  = ptr({int(walk_address, 16)});  // ensure a NativePointer from Python value
    var target = base.add(rel);               // base + offset

    Interceptor.attach(target, {{
      onEnter: function(args) {{
        // 32/64-bit friendly: pick ecx or rcx
        var reg = this.context.ecx || this.context.rcx;
        if (!reg) {{
          send({{error: "No ECX/RCX in context"}});
          return;
        }}
        var xAddress = reg.add(0x08);
        var yAddress = xAddress.add(0x04);
        send({{x_address: xAddress.toString(), y_address: yAddress.toString()}});
      }}
    }});
    """

    script = session.create_script(script_code)
    script.on('message', on_message_xy)
    script.load()

    while xstarted == 0:
        time.sleep(0.01)

    print("Session completed and detached.")


def on_message_directional(message, data):
    global directional_address, xstarted
    if message['type'] == 'send':
        payload = message['payload']
        directional_address = int(payload.get('directional_address'), 16)
        character_direction = payload.get('character_direction')
        if debug == 1:
            print(f"Character Direction Address: {directional_address}")
            print(f"Character Direction Value: {character_direction}")
        xstarted = 2
        session.detach()
    elif message['type'] == 'error':
        print(f"Error: {message['stack']}")

def start_frida_session_directional(target_address):
    global session
    session = frida.attach("Endless.exe")
    print("Directional Started - Waiting for mov [ebx+55],dl to execute")

    script_code = f"""
    var mod = null;
    try {{ mod = Process.getModuleByName("Endless.exe"); }} catch(e) {{
      var mods = Process.enumerateModules(); mod = mods.length ? mods[0] : null;
    }}
    if (!mod) throw new Error("Could not find module base for Endless.exe");

    var base = mod.base;
    var rel  = ptr({int(target_address, 16)});
    var target = base.add(rel);

    Interceptor.attach(target, {{
      onEnter: function(args) {{
        var ebx = this.context.ebx || this.context.rbx; // x86/x64 friendly
        if (!ebx) {{ send({{error: "No EBX/RBX in context"}}); return; }}
        var characterDirectionAddress = ebx.add(0x55);
        var characterDirection = characterDirectionAddress.readU8();
        send({{
          directional_address: characterDirectionAddress.toString(),
          character_direction: characterDirection.toString()
        }});
      }}
    }});
    """

    script = session.create_script(script_code)
    script.on('message', on_message_directional)
    script.load()

    while xstarted == 1:
        time.sleep(0.01)

    print("Directional Session Completed.")

def patch_adds_with_nops():
    # attach to the process
    session = frida.attach("Endless.exe")

    # inline the two absolute addresses you want to NOP
    js = """
    [0x005F30E2, 0x005F30FC].forEach(function(addr) {
        // make the 7 bytes at addr writeable
        Memory.protect(ptr(addr), 7, 'rwx');
        // overwrite them with NOP (0x90)
        for (var i = 0; i < 7; i++) {
          Memory.writeU8(ptr(addr).add(i), 0x90);
        }
        // restore as RX
        Memory.protect(ptr(addr), 7, 'r-x');
    });
    """

    script = session.create_script(js)
    script.load()
    session.detach()

def start_frida_speech_monitor():
    """
    Hooks the game's speech writer(s) and streams text lines back to Python.
    We then associate each line with the nearest visible NPC on the current map snapshot.
    """
    import frida, time
    global current_target_npc
    
    PROCESS_NAME = "Endless.exe"
    MODULE_NAME  = "Endless.exe"
    WRITE_OFFSETS = [0x1F293D]       # keep/tune these as you discover more sites
    SPEECH_TEXTPTR_OFFSET = 0x24

    # Tunables (mirrored from your scanner)
    DEDUP_WINDOW = 4.0
    STABILIZE_MS = 900
    TICK_MS = 45
    REQUIRE_SAME_TICKS = 3
    MAX_LINES = 8
    MAX_STR_LEN = 512

    FRIDA_JS = f"""
    'use strict';
    const moduleName = "{MODULE_NAME}";
    const base = Module.findBaseAddress(moduleName);
    if (!base) throw new Error("Module not found: " + moduleName);
    const WRITE_OFFSETS = [{", ".join("0x%X" % o for o in WRITE_OFFSETS)}];
    const OFF_TXT = ptr("0x{SPEECH_TEXTPTR_OFFSET:X}");
    const MAX_LINES = {MAX_LINES};
    const MAX_STR_LEN = {MAX_STR_LEN};
    const STABILIZE_MS = {STABILIZE_MS};
    const TICK_MS = {TICK_MS};
    const REQUIRE_SAME_TICKS = {REQUIRE_SAME_TICKS};

    function notNull(p) {{ return p && !p.isNull(); }}
    function safePtr(a) {{ try {{ return Memory.readPointer(a); }} catch(_) {{ return NULL; }} }}
    function readUtf8Safe(p) {{
      if (!notNull(p)) return "";
      try {{
        let s = Memory.readUtf8String(p);
        if (!s) return "";
        if (s.length > MAX_STR_LEN) s = s.slice(0, MAX_STR_LEN);
        s = s.replace(/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]/g, "");
        return s.trim();
      }} catch(_) {{ return ""; }}
    }}

    function readUntilNull(arrBase) {{
      const lines = [];
      const psz = Process.pointerSize;
      for (let i = 0; i < MAX_LINES; i++) {{
        let tp;
        try {{ tp = Memory.readPointer(arrBase.add(i * psz)); }} catch(_) {{ break; }}
        if (!notNull(tp)) break;
        let s = readUtf8Safe(tp);
        if (!s) {{
          const q = safePtr(tp);
          if (notNull(q)) s = readUtf8Safe(q);
        }}
        if (s) lines.push(s);
      }}
      return lines.length ? lines.join("\\n") : null;
    }}

    function readAllLines(container) {{
      const inlineBase = container.add(OFF_TXT);
      const A = readUntilNull(inlineBase);
      const arrPtr = safePtr(inlineBase);
      const B = notNull(arrPtr) ? readUntilNull(arrPtr) : null;
      if (A && B) return (B.length > A.length) ? B : A;
      return A || B || null;
    }}

    function readSingle(container) {{
      const p = safePtr(container.add(OFF_TXT));
      let s = readUtf8Safe(p);
      if (!s) {{
        const q = safePtr(p);
        if (notNull(q)) s = readUtf8Safe(q);
      }}
      return s || null;
    }}

    function smartRead(container) {{
      const a = readAllLines(container) || "";
      const b = readSingle(container)    || "";
      return (a.length >= b.length ? a : b) || null;
    }}

    function readStable(container) {{
      return new Promise(resolve => {{
        const deadline = Date.now() + STABILIZE_MS;
        let best = "", last = "", same = 0;
        const itv = setInterval(() => {{
          const s = smartRead(container) || "";
          if (s.length > best.length) best = s;
          same = (s === last) ? (same + 1) : 0;
          last = s;
          if (Date.now() > deadline || same >= REQUIRE_SAME_TICKS) {{
            clearInterval(itv);
            resolve((best || s).trim());
          }}
        }}, TICK_MS);
      }});
    }}

    let lastPrinted = "";
    function emit(text) {{
      const t = (text || "").trim();
      if (!t || t === lastPrinted) return;
      lastPrinted = t;
      send({{ type: "speech", text: t }});
    }}

    for (const off of WRITE_OFFSETS) {{
      Interceptor.attach(base.add(off), {{
        onEnter() {{
          const container = ptr(this.context.ecx);
          if (!container.isNull()) readStable(container).then(emit);
        }}
      }});
    }}

    send({{ type: "ready" }});
    """

    # Simple deduper on the Python side too (tiny guard)
    class _Deduper:
        def __init__(self, window_s=DEDUP_WINDOW):
            self.window = window_s
            self.seen = {}
        def accept(self, text):
            now = time.time()
            last = self.seen.get(text)
            if last and (now - last) < self.window:
                return False
            self.seen[text] = now
            # prune
            for k in list(self.seen):
                if now - self.seen[k] > self.window:
                    self.seen.pop(k, None)
            return True

    deduper = _Deduper()

    def _on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "ready":
                print("[speech] frida ready (hooks installed).")
            elif payload.get("type") == "speech":
                t = (payload.get("text") or "").strip()
                if t and deduper.accept(t):
                    # minimal behaviour: print and record; DO NOT touch any targeting globals
                    ts = time.time()
                    print(f"[speech] {t}")
                    try:
                        # keep a tiny recent history for the UI/diagnostics
                        recent_speech_log.append((ts, None, t))   # addr=None (no association)
                        npc_last_speech[None] = {"text": t, "ts": ts}
                    except Exception:
                        pass

                    # trigger quarantine if any pattern matches
                    if any(re.search(pat, t, flags=re.IGNORECASE) for pat in TRIGGERS):
                        global speech_quarantine_until, current_target_npc
                        speech_quarantine_until = time.time() + 120

                        # immediate belt-and-suspenders: release CTRL and forget current target
                        try:
                            release_key('ctrl')
                        except Exception:
                            pass
                        current_target_npc = None

                        print("[bot-detect] Quarantine activated for 2 minutes")

        elif message.get("type") == "error":
            print("[speech] frida script error:", message.get("stack") or message)

    # Attach and keep the session alive in this thread
    session = frida.attach(PROCESS_NAME)
    script = session.create_script(FRIDA_JS)
    script.on("message", _on_message)
    script.load()
    print("[speech] hooks running.")
    try:
        while True:
            time.sleep(1.0)
    except Exception:
        pass

class PlayerDataManager:
    def __init__(self):
        self.data = {
            "x": 0,
            "y": 0,
            "direction": 0
        }

    def update(self, x, y, direction):
        self.data["x"] = x
        self.data["y"] = y
        self.data["direction"] = direction

    def get_data(self):
        return self.data

class AddressManager:
    def __init__(self):
        self.addresses = {}
        self._protection_default = 3  # seconds
        self.ignore_protection = False
        # v5.3 parity: locking + history/logging
        self._lock = threading.Lock()
        self._removal_history = []
        self._history_max = 50

    def add_address(self, address):
        address1 = int(address, 16)
        address2 = address1 + 2
        address1_hex = hex(address1).upper()
        address2_hex = hex(address2).upper()
        with self._lock:
            if address1_hex not in self.addresses:
                self.addresses[address1_hex] = {
                    "paired_address": address2_hex,
                    "last_x": None,
                    "last_y": None,
                    "last_moved": time.time(),
                    "is_dead_counter": 0,
                    "last_is_dead_value": None,
                    "first_seen_ts": time.time(),
                    "oob_strikes": 0,
                    "last_good_xy": None,
                    "last_unique_id": None,
                    "got_hit": None,
                    "protected_until": None,
                    "protected_cleared_at": None,
                }
                return True
            return False

    def set_ignore_protection(self, flag: bool):
        self.ignore_protection = bool(flag)

    def is_protected(self, addr_hex: str) -> bool:
        if globals().get("IGNORE_PROTECTION", False):
            return False
        if self.ignore_protection:
            return False
        with self._lock:
            st = self.addresses.get(addr_hex)
        if not st:
            return False
        now = time.time()
        pu = st.get("protected_until")
        if pu and now < pu:
            return True
        # when a window ends, start a tiny grace to avoid instant retarget
        with self._lock:
            if pu and now >= pu:
                st["protected_until"] = None
                st["protected_cleared_at"] = now
            pc = st.get("protected_cleared_at")
        if pc and (now - pc) < POST_PROTECT_GRACE_S:
            return True
        return False

    def mark_protected(self, addr_hex: str, seconds: int | None = None, reason: str = "got_hit", meta: dict | None = None):
        secs = seconds if seconds is not None else self._protection_default
        with self._lock:
            st = self.addresses.get(addr_hex)
            if not st:
                return False
            st["protected_until"] = time.time() + max(1, secs)
            st["protected_cleared_at"] = None
            # v5.3 parity: log protection event
            self._log_removal(addr_hex, f"protected:{reason}", meta or {}, dict(st))
            return True

    def protection_seconds_left(self, addr_hex: str) -> int:
        with self._lock:
            st = self.addresses.get(addr_hex)
        if not st or not st.get("protected_until"):
            return 0
        return max(0, int(st["protected_until"] - time.time()))

    def remove_address(self, address, reason: str = "unspecified", meta: dict | None = None):
        address1 = int(address, 16)
        address1_hex = hex(address1).upper()
        with self._lock:
            if address1_hex in self.addresses:
                last_state = dict(self.addresses[address1_hex])
                del self.addresses[address1_hex]
                self._log_removal(address1_hex, reason, meta or {}, last_state)
                return True
            return False

    def list_addresses(self):
        # Keep existing shape but make thread-safe
        with self._lock:
            return [{"X": x, "Y": data["paired_address"]} for x, data in self.addresses.items()]

    # --- v5.3-style logging helpers ---
    def _log_removal(self, addr_hex: str, reason: str, meta: dict | None = None, last_state: dict | None = None):
        entry = {
            "ts": time.time(),
            "address": addr_hex,
            "reason": reason,
            "meta": meta or {},
            "last_state": last_state or {},
        }
        self._removal_history.append(entry)
        if len(self._removal_history) > self._history_max:
            self._removal_history = self._removal_history[-self._history_max:]

    def get_removal_history(self):
        # small, read-only copy for inspection
        with self._lock:
            return list(self._removal_history)

manager = AddressManager()
player_data_manager = PlayerDataManager()
map_data = []

class ScrollableFrame(ttk.Frame):
    """A vertical scrollable frame for stacking sections in a single column."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.interior = ttk.Frame(self.canvas)

        self.canvas.configure(yscrollcommand=self.vbar.set)

        # store the window id so we can synchronize its width to the canvas
        self._win_id = self.canvas.create_window((0, 0), window=self.interior, anchor="nw")

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vbar.grid(row=0, column=1, sticky="ns")

        # allow the canvas to expand
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # keep scrollregion + interior width in sync
        def _on_interior_configure(event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            # match interior width to visible canvas width (single-column behavior)
            self.canvas.itemconfigure(self._win_id, width=self.canvas.winfo_width())
        self.interior.bind("<Configure>", _on_interior_configure)

        def _on_canvas_configure(event):
            self.canvas.itemconfigure(self._win_id, width=event.width)
        self.canvas.bind("<Configure>", _on_canvas_configure)

        # mouse wheel support, scoped to this widget
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _):
        # Windows / macOS wheel
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        # Linux wheel
        self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)

    def _unbind_wheel(self, _):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event):
        # Windows uses multiples of 120; macOS uses small deltas (just works)
        self.canvas.yview_scroll(-1 * (event.delta // 120 if event.delta else 1), "units")

    def _on_mousewheel_linux(self, event):
        self.canvas.yview_scroll(-1 if event.num == 4 else 1, "units")


class PlayerDataPopup:
    def __init__(self, player_data_manager):
        self.player_data_manager = player_data_manager
        self.root = ThemedTk(theme="black")
        self.root.title("Player Data")
        self.ignore_prot_var = tk.BooleanVar(value=IGNORE_PROTECTION)


        # --- Window sizing (make it resizable and visible) ---
        self.root.geometry("1120x720")   # initial size (taller? bump second number)
        self.root.minsize(980, 620)      # keeps panes from collapsing
        self.root.resizable(True, True)

        # Shared label caches
        self.labels = {}
        self.stats_labels = {}

        # Backed by globals
        self.boss_aggro_var = tk.BooleanVar(value=BOSS_AGGRO_TOGGLE)

        self.create_widgets()
        self.create_styles()  # ← ensures theme stays 'clam'
        self.update_ui()
        self._place_left_center()
        self.root.after_idle(self._place_left_center)

        # Hotkeys + visibility rescue
        self.root.bind("<F12>", self._bring_to_front)
        self.root.after(0, self._ensure_visible)
        self.root.after(50, self._bring_to_front)

        # Save settings on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ---------- visibility helpers ----------
    def _bring_to_front(self, *_):
        try:
            self.root.deiconify()
        except Exception:
            pass
        self.root.lift()
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.after(400, lambda: self.root.attributes("-topmost", False))

    def _ensure_visible(self):
        """If window is off-screen (OS restored weird coords), re-center it."""
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        try:
            g = self.root.geometry()  # "WxH+X+Y"
            size, _, _ = g.partition('+')
            w, _, h = size.partition('x')
            w, h = int(w), int(h)
            parts = g.split('+')
            x = int(parts[1]) if len(parts) > 1 else 100
            y = int(parts[2]) if len(parts) > 2 else 100
        except Exception:
            w, h, x, y = 1120, 720, 100, 100
        off = (x > sw - 40) or (y > sh - 40) or (x + w < 40) or (y + h < 40)
        if off:
            nx = max(0, (sw - w) // 2)
            ny = max(0, (sh - h) // 2)
            self.root.geometry(f"{w}x{h}+{nx}+{ny}")

    def _place_left_center(self):
        """Force the window near the left edge, vertically centered."""
        # Make sure sizes are computed
        self.root.update_idletasks()

        # Use current size if available, otherwise fall back to sane defaults
        w = max(self.root.winfo_width(),  1120)
        h = max(self.root.winfo_height(),  720)

        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()

        # ~5% from the left edge, vertically centered
        x = max(0, int(sw * 0.05))
        y = max(0, (sh - h) // 2)

        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def create_widgets(self):
        # ---------- window sizing ----------
        self.root.geometry("1120x720")   # normal window
        self.root.minsize(920, 600)
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        PADX, PADY = (10, 10), (8, 8)

        # ---------- 2-pane layout (left = scroll column, right = map+info+chat) ----------
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.grid(row=0, column=0, sticky="nsew")

        # LEFT: scrollable controls
        left_container = ttk.Frame(paned)
        paned.add(left_container, weight=3)
        left_container.rowconfigure(0, weight=1)
        left_container.columnconfigure(0, weight=1)

        left = ScrollableFrame(left_container)
        left.grid(row=0, column=0, sticky="nsew")

        def add_section(title):
            f = ttk.LabelFrame(left.interior, text=title, padding=6)
            f.grid(sticky="ew", padx=PADX, pady=PADY)
            f.columnconfigure(0, weight=1)
            return f

        # RIGHT: make the whole right side scrollable to avoid "invisible chat" on short windows
        right_scroll = ScrollableFrame(paned)
        paned.add(right_scroll, weight=2)
        right = right_scroll.interior
        right.rowconfigure(0, weight=0)  # map
        right.rowconfigure(1, weight=0)  # info
        right.rowconfigure(2, weight=1)  # chat grows
        right.columnconfigure(0, weight=1)
        # Prevent the chat row from starting at 0 height
        right.grid_rowconfigure(2, minsize=240)

        # --- Paned constraints (initial sash + minsizes) ---
        try:
            paned.paneconfigure(left_container, minsize=360)
            # was: paned.paneconfigure(right,          minsize=520)
            paned.paneconfigure(right_scroll,   minsize=520)   # ← point at the actual pane
            self.root.after_idle(lambda: (paned.update_idletasks(), paned.sashpos(0, 560)))
        except Exception:
            pass

        # ================= LEFT SCROLL COLUMN =================
        # 1) Bot Control (TOP)
        bot = add_section("Bot Control")
        self.start_bot_button = ttk.Button(bot, text="Start", command=self.on_start_bot, style="success.TButton")
        self.start_bot_button.grid(row=0, column=0, sticky="w", padx=(0,6))
        self.stop_bot_button  = ttk.Button(bot, text="Stop",  command=self.on_stop_bot,  style="danger.TButton", state=tk.DISABLED)
        self.stop_bot_button.grid(row=0, column=1, sticky="w")
        self.bot_status_label = ttk.Label(bot, text="Status: STOPPED", foreground="red")
        self.bot_status_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5,0))

        # 2) Sit Timer
        sit = add_section("Sit Timer Configuration")
        ttk.Label(sit, text="Sit (seconds):").grid(row=0, column=0, sticky="w")
        self.sit_timer_var = tk.StringVar(value=str(SIT_TIMER_SECONDS))
        e = ttk.Entry(sit, textvariable=self.sit_timer_var, width=8)
        e.grid(row=0, column=1, sticky="w", padx=(8,0))
        e.bind("<FocusOut>", self.on_sit_timer_change)
        e.bind("<Return>",   self.on_sit_timer_change)
        self.sit_timer_status = ttk.Label(sit, text=f"Current: {SIT_TIMER_SECONDS}s", foreground="blue")
        self.sit_timer_status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5,0))

        # 3) Force Movement
        force_section = add_section("Force Movement Tuning")
        ttk.Label(force_section, text="Hold time (seconds):").grid(row=0, column=0, sticky="w")
        self.force_movement_var = tk.StringVar(value=f"{float(FORCE_MOVEMENT_SECONDS):.4f}")
        self.force_movement_entry = ttk.Entry(force_section, textvariable=self.force_movement_var, width=8)
        self.force_movement_entry.grid(row=0, column=1, sticky="w", padx=(8,0))
        self.force_movement_entry.bind("<FocusOut>", self.on_force_movement_change)
        self.force_movement_entry.bind("<Return>",   self.on_force_movement_change)
        self.force_movement_status = ttk.Label(
            force_section,
            text=f"Current: {float(FORCE_MOVEMENT_SECONDS):.4f}s",
            foreground="blue"
        )
        self.force_movement_status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5,0))

        # 4) Stale NPC
        stale = add_section("Stale NPC")
        ttk.Label(stale, text="NPC cleanup timer (seconds):").grid(row=0, column=0, sticky="w")
        self.last_moved_timer_var = tk.StringVar(value=str(LAST_MOVED_TIMER_SECONDS))
        e2 = ttk.Entry(stale, textvariable=self.last_moved_timer_var, width=8)
        e2.grid(row=0, column=1, sticky="w", padx=(8,0))
        e2.bind("<FocusOut>", self.on_last_moved_timer_change)
        e2.bind("<Return>",   self.on_last_moved_timer_change)
        self.last_moved_timer_status = ttk.Label(stale, text=f"Current: {LAST_MOVED_TIMER_SECONDS}s", foreground="blue")
        self.last_moved_timer_status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5,0))

        # 5) NPC Target Management
        npc = add_section("NPC Target Management")
        ttk.Label(npc, text="Add NPC ID:").grid(row=0, column=0, sticky="w")
        self.add_npc_var = tk.StringVar()
        add_npc_entry = ttk.Entry(npc, textvariable=self.add_npc_var, width=8)
        add_npc_entry.grid(row=0, column=1, sticky="w", padx=(5,0))
        add_npc_entry.bind("<Return>", self.add_npc_target)
        ttk.Button(npc, text="Add", command=self.add_npc_target).grid(row=0, column=2, sticky="w", padx=(5,0))

        ttk.Label(npc, text="Remove NPC ID:").grid(row=1, column=0, sticky="w", pady=(5,0))
        self.remove_npc_var = tk.StringVar()
        remove_npc_entry = ttk.Entry(npc, textvariable=self.remove_npc_var, width=8)
        remove_npc_entry.grid(row=1, column=1, sticky="w", padx=(5,0), pady=(5,0))
        remove_npc_entry.bind("<Return>", self.remove_npc_target)
        ttk.Button(npc, text="Remove", command=self.remove_npc_target).grid(row=1, column=2, sticky="w", padx=(5,0), pady=(5,0))

        ttk.Label(npc, text="Current targets:").grid(row=2, column=0, sticky="w", pady=(6,0))
        self.targets_display = None

        # 6) Home Routine (with Early Stand-Up moved here)
        home_toggle = add_section("Home Routine (Run After Kill)")
        self.home_toggle_var = tk.BooleanVar(value=RUN_HOME_AFTER_KILL)
        ttk.Checkbutton(home_toggle, text="Enable (Bossing)",
                        variable=self.home_toggle_var, command=self.on_home_toggle).grid(row=0, column=0, sticky="w")

        ttk.Label(home_toggle, text="Enable early stand-up when NPCs detected:").grid(row=1, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(home_toggle, text="Enable",
                        variable=self.boss_aggro_var,
                        command=self.on_boss_aggro_toggle).grid(row=1, column=1, sticky="w", padx=(10,0), pady=(6,0))
        self.boss_aggro_status = ttk.Label(
            home_toggle,
            text=("Status: ENABLED" if self.boss_aggro_var.get() else "Status: DISABLED"),
            foreground=("green" if self.boss_aggro_var.get() else "red")
        )
        self.boss_aggro_status.grid(row=2, column=0, columnspan=2, sticky="w", pady=(5,0))

        # --- F5 tap count after sitting ---
        ttk.Label(home_toggle, text="F5 taps after F11:").grid(row=3, column=0, sticky="w", pady=(6,0))
        self.f5_taps_var = tk.StringVar(value=str(F5_TAP_COUNT))
        f5_entry = ttk.Entry(home_toggle, textvariable=self.f5_taps_var, width=8)
        f5_entry.grid(row=3, column=1, sticky="w", padx=(10,0))
        f5_entry.bind("<FocusOut>", self.on_f5_taps_change)
        f5_entry.bind("<Return>",   self.on_f5_taps_change)
        self.f5_taps_status = ttk.Label(home_toggle, text=f"Current: {F5_TAP_COUNT}", foreground="blue")
        self.f5_taps_status.grid(row=4, column=0, columnspan=2, sticky="w", pady=(3,0))

        # --- Wander timeout (seconds) ---
        ttk.Label(home_toggle, text="Wander timeout (s) before going Home:").grid(row=5, column=0, sticky="w", pady=(6,0))
        self.wander_timeout_var = tk.StringVar(value=str(WANDER_TIMEOUT_S))
        wander_entry = ttk.Entry(home_toggle, textvariable=self.wander_timeout_var, width=8)
        wander_entry.grid(row=5, column=1, sticky="w", padx=(10,0))
        wander_entry.bind("<FocusOut>", self.on_wander_timeout_change)
        wander_entry.bind("<Return>",   self.on_wander_timeout_change)
        self.wander_timeout_status = ttk.Label(home_toggle, text=f"Current: {WANDER_TIMEOUT_S}s", foreground="blue")
        self.wander_timeout_status.grid(row=6, column=0, columnspan=2, sticky="w", pady=(3,0))

        # --- Home after N kills ---
        ttk.Label(home_toggle, text="Go Home after N kills:").grid(row=7, column=0, sticky="w", pady=(6,0))
        self.kills_per_home_var = tk.StringVar(value=str(HOME_AFTER_KILLS_N))
        kills_entry = ttk.Entry(home_toggle, textvariable=self.kills_per_home_var, width=8)
        kills_entry.grid(row=7, column=1, sticky="w", padx=(10,0))
        kills_entry.bind("<FocusOut>", self.on_kills_per_home_change)
        kills_entry.bind("<Return>",   self.on_kills_per_home_change)
        self.kills_per_home_status = ttk.Label(home_toggle, text=f"Current: {HOME_AFTER_KILLS_N}", foreground="blue")
        self.kills_per_home_status.grid(row=8, column=0, columnspan=2, sticky="w", pady=(3,0))

        # 6) Range
        range_f = add_section("Range")
        ttk.Label(range_f, text="Tiles (1-5):").grid(row=0, column=0, sticky="w")
        self.flank_range_var = tk.StringVar(value=str(FLANK_RANGE))
        flank_entry = ttk.Entry(range_f, textvariable=self.flank_range_var, width=6)
        flank_entry.grid(row=0, column=1, sticky="w", padx=(10,0))
        flank_entry.bind("<FocusOut>", self.on_flank_range_change)
        flank_entry.bind("<Return>",   self.on_flank_range_change)
        self.flank_range_status = ttk.Label(range_f, text=f"Current: {FLANK_RANGE}", foreground="blue")
        self.flank_range_status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5,0))

        # 7) Corpse/Loot Clicking + Fast Click
        click = add_section("Corpse/Loot Clicking")
        self.click_toggle_var = tk.BooleanVar(value=CLICKING_ENABLED)
        ttk.Checkbutton(click, text="Enable clicking after kills",
                        variable=self.click_toggle_var, command=self.on_click_toggle).grid(row=0, column=0, sticky="w")

        self.fast_click_var = tk.BooleanVar(value=FAST_CLICK)
        ttk.Checkbutton(click, text="Fast click burst",
                        variable=self.fast_click_var, command=self.on_fast_click_toggle).grid(row=1, column=0, sticky="w", pady=(4,0))

        params = ttk.Frame(click)
        params.grid(row=2, column=0, sticky="w", pady=(2,0))
        ttk.Label(params, text="Burst:").grid(row=0, column=0, sticky="w")

        self.fast_click_burst_var = tk.StringVar(value=str(FAST_CLICK_BURST_COUNT))
        self.fast_click_burst_entry = ttk.Entry(params, textvariable=self.fast_click_burst_var, width=5)
        self.fast_click_burst_entry.grid(row=0, column=1, sticky="w", padx=(4,12))
        self.fast_click_burst_entry.bind("<FocusOut>", self.on_fast_click_params_change)
        self.fast_click_burst_entry.bind("<Return>",   self.on_fast_click_params_change)

        ttk.Label(params, text="Gap (s):").grid(row=0, column=2, sticky="w")
        self.fast_click_gap_var = tk.StringVar(value=str(FAST_CLICK_GAP_S))
        self.fast_click_gap_entry = ttk.Entry(params, textvariable=self.fast_click_gap_var, width=6)
        self.fast_click_gap_entry.grid(row=0, column=3, sticky="w", padx=(4,0))
        self.fast_click_gap_entry.bind("<FocusOut>", self.on_fast_click_params_change)
        self.fast_click_gap_entry.bind("<Return>",   self.on_fast_click_params_change)


        # 8) Home Coordinates
        home = add_section("Home Coordinates")
        ttk.Label(home, text="X:").grid(row=0, column=0, sticky="w")
        self.home_x_var = tk.StringVar(value=str(HOME_POS[0]))
        ttk.Entry(home, textvariable=self.home_x_var, width=6).grid(row=0, column=1, sticky="w", padx=(5,0))
        ttk.Label(home, text="Y:").grid(row=0, column=2, sticky="w", padx=(10,0))
        self.home_y_var = tk.StringVar(value=str(HOME_POS[1]))
        ttk.Entry(home, textvariable=self.home_y_var, width=6).grid(row=0, column=3, sticky="w", padx=(5,0))
        ttk.Button(home, text="Apply",            command=self.on_home_change).grid(row=0, column=4, sticky="w", padx=(10,0))
        ttk.Button(home, text="Set from current", command=self.set_home_from_current).grid(row=0, column=5, sticky="w", padx=(5,0))
        self.home_status = ttk.Label(home, text=f"Current: ({HOME_POS[0]}, {HOME_POS[1]})", foreground="blue")
        self.home_status.grid(row=1, column=0, columnspan=6, sticky="w", pady=(5,0))

        self.protection_status = ttk.Label(home, text="Protection: ENABLED", foreground="green")
        self.protection_status.grid(row=2, column=0, columnspan=6, sticky="w", pady=(6,2))

        # checkbox to enable/disable protection
        self.ignore_prot_var = tk.BooleanVar(value=IGNORE_PROTECTION)
        ttk.Checkbutton(
            home,
            text="Disable protected NPCs (boss mode)",
            variable=self.ignore_prot_var,
            command=self.on_protection_toggle  # see handler below
        ).grid(row=3, column=0, columnspan=6, sticky="w")
            
            
        # =============== Task Mode (GUI) - Replaces Harvest Mode ===============
        task = add_section("Task Mode")

        # Row 0: Start/Stop
        task_btns = ttk.Frame(task); task_btns.grid(row=0, column=0, columnspan=6, sticky="w", pady=(2,6))
        self.task_start = ttk.Button(task_btns, text="Start Task Mode", command=self.on_task_start)
        self.task_stop  = ttk.Button(task_btns, text="Stop", command=self.on_task_stop, state=tk.DISABLED)
        self.task_start.grid(row=0, column=0, padx=(0,8))
        self.task_stop.grid(row=0, column=1)
        
        # Row 1: Loop count
        ttk.Label(task, text="Loops:").grid(row=1, column=0, sticky="w", pady=(4,0))
        self.task_loops_var = tk.StringVar(value="1000")
        ttk.Entry(task, textvariable=self.task_loops_var, width=8).grid(row=1, column=1, sticky="w", padx=(4,10), pady=(4,0))
        ttk.Label(task, text="Combat Timer (s):").grid(row=1, column=2, sticky="w", pady=(4,0))
        self.combat_timer_var = tk.StringVar(value=str(COMBAT_TASK_DURATION))
        combat_timer_entry = ttk.Entry(task, textvariable=self.combat_timer_var, width=8)
        combat_timer_entry.grid(row=1, column=3, sticky="w", padx=(4,10), pady=(4,0))
        combat_timer_entry.bind("<FocusOut>", self.on_combat_timer_change)
        combat_timer_entry.bind("<Return>",   self.on_combat_timer_change)

        # Row 2: Task inputs
        ttk.Label(task, text="X:").grid(row=2, column=0, sticky="w", pady=(4,0))
        self.task_x_var = tk.StringVar()
        ttk.Entry(task, textvariable=self.task_x_var, width=6).grid(row=2, column=1, sticky="w", padx=(4,10), pady=(4,0))

        ttk.Label(task, text="Y:").grid(row=2, column=2, sticky="w", pady=(4,0))
        self.task_y_var = tk.StringVar()
        ttk.Entry(task, textvariable=self.task_y_var, width=6).grid(row=2, column=3, sticky="w", padx=(4,10), pady=(4,0))

        ttk.Label(task, text="Action:").grid(row=2, column=4, sticky="w", pady=(4,0))
        self.task_action_var = tk.StringVar(value="Click")
        self.task_action = ttk.Combobox(task, textvariable=self.task_action_var, width=10, state="readonly",
                                    values=["Click", "DoubleClick", "RightClick", "Ctrl", "F1", "F2", "Walk", "SIT", "Warp", "Combat"])
        self.task_action.grid(row=2, column=5, sticky="w", pady=(4,0))

        # Row 3: Direction (for actions that need it)
        ttk.Label(task, text="Direction:").grid(row=3, column=0, sticky="w", pady=(4,0))
        self.task_dir_var = tk.StringVar(value="down")
        self.task_dir = ttk.Combobox(task, textvariable=self.task_dir_var, width=8, state="readonly",
                                    values=["down", "left", "up", "right"])
        self.task_dir.grid(row=3, column=1, sticky="w", padx=(4,10), pady=(4,0))

        # Row 4: Add/Remove
        self.task_add = ttk.Button(task, text="Add Task", command=self.on_task_add)
        self.task_add.grid(row=4, column=0, columnspan=2, sticky="w", pady=(6,4))
        self.task_add_at_location = ttk.Button(task, text="Add at Current Location", command=self.on_task_add_at_current)
        self.task_add_at_location.grid(row=4, column=2, columnspan=2, sticky="w", pady=(6,4), padx=(10,0))
        self.task_remove = ttk.Button(task, text="Remove Selected", command=self.on_task_remove)
        self.task_remove.grid(row=5, column=0, columnspan=2, sticky="w", pady=(6,4))
        self.task_save = ttk.Button(task, text="Save Tasks", command=self.on_task_save)
        self.task_save.grid(row=5, column=2, columnspan=2, sticky="w", pady=(6,4), padx=(10,0))
        self.task_reset_clicks = ttk.Button(task, text="Reset Click Locations", command=self.on_task_reset_clicks)
        self.task_reset_clicks.grid(row=5, column=4, columnspan=2, sticky="w", pady=(6,4), padx=(10,0))
        self.task_record_click = ttk.Button(task, text="Record Click for Selected", command=self.on_task_record_click)
        self.task_record_click.grid(row=6, column=0, columnspan=3, sticky="w", pady=(6,4))

        # Row 7: list
        ttk.Label(task, text="Configured tasks:").grid(row=7, column=0, columnspan=6, sticky="w", pady=(4,0))
        self.task_list = tk.Listbox(task, height=7)
        self.task_list.grid(row=8, column=0, columnspan=6, sticky="nsew", pady=(4,0))
        task.rowconfigure(8, weight=1)
        for c in range(6): task.columnconfigure(c, weight=1)

        # populate on show
        self.refresh_task_list()

        # ================= RIGHT: MAP + INFO + CHAT =================
        # Map
        map_frame = ttk.LabelFrame(right, text="Map View", padding=6)
        map_frame.grid(row=0, column=0, sticky="nw", padx=PADX, pady=PADY)
        self.canvas = tk.Canvas(map_frame, width=260, height=260, bg="white")
        self.canvas.grid(row=0, column=0, sticky="nw")

        # Player Data + Player Stats
        info_row = ttk.Frame(right)
        info_row.grid(row=1, column=0, sticky="nsew", padx=PADX, pady=PADY)
        info_row.columnconfigure(0, weight=0)
        info_row.columnconfigure(1, weight=1)

        player_frame = ttk.LabelFrame(info_row, text="Player Data", padding=6)
        player_frame.grid(row=0, column=0, sticky="nw", padx=(0, 12))
        for i, text in enumerate(["X", "Y", "Direction"]):
            ttk.Label(player_frame, text=f"{text}:").grid(row=i, column=0, sticky="w")
            v = ttk.Label(player_frame, text="0")
            v.grid(row=i, column=1, sticky="e", padx=(8,0))
            self.labels[text] = v

        # >>> REWRITTEN: compact, multi-column Player Stats
        stats_frame = ttk.LabelFrame(info_row, text="Player Stats", padding=6)
        stats_frame.grid(row=0, column=1, sticky="nsew")
        # configure columns later after we know how many

        stats = [
            "exp","level","tnl","weight","vit","dex","acc","def","pwr","crit",
            "armor","eva","hit_rate","max_dmg","min_dmg","aura","max_hp","max_mana","eon"
        ]

        # how many stat *columns* (each stat column = label + value)
        STAT_COLS = 2  # change to 3 to make it even shorter
        rows_per_col = (len(stats) + STAT_COLS - 1) // STAT_COLS  # ceil

        self.stats_labels = {}
        for idx, stat in enumerate(stats):
            r = idx % rows_per_col
            c = (idx // rows_per_col) * 2  # each stat uses 2 grid columns (label, value)

            ttk.Label(stats_frame, text=f"{stat.upper()}:").grid(
                row=r, column=c, sticky="w", padx=(0,6), pady=(2,1)
            )
            lbl = ttk.Label(stats_frame, text="N/A", width=7, anchor="e")
            lbl.grid(row=r, column=c+1, sticky="e", pady=(2,1))
            self.stats_labels[stat] = lbl

        # make value columns expand slightly so it breathes
        for i in range(STAT_COLS * 2):
            stats_frame.columnconfigure(i, weight=1 if i % 2 else 0)


        # Chat (fills the rest; its own scrollbar)
        chat_frame = ttk.LabelFrame(right, text="Recent Chat", padding=6)
        chat_frame.grid(row=2, column=0, sticky="nsew", padx=PADX, pady=PADY)
        chat_frame.rowconfigure(0, weight=1)
        chat_frame.columnconfigure(0, weight=1)

        chat_wrap = ttk.Frame(chat_frame)
        chat_wrap.grid(row=0, column=0, sticky="nsew")
        chat_wrap.rowconfigure(0, weight=1)
        chat_wrap.columnconfigure(0, weight=1)

        self.chat_list = tk.Listbox(chat_wrap, height=12)  # ensure visible at first paint
        self.chat_list.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(chat_wrap, orient="vertical", command=self.chat_list.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.chat_list.configure(yscrollcommand=sb.set)

        self.last_speech_lbl = ttk.Label(chat_frame, text="Last:")
        self.last_speech_lbl.grid(row=1, column=0, sticky="w", pady=(6,0))

    def on_home_toggle(self):
        global RUN_HOME_AFTER_KILL
        RUN_HOME_AFTER_KILL = self.home_toggle_var.get()
        print(f"[TOGGLE] RUN_HOME_AFTER_KILL = {RUN_HOME_AFTER_KILL}")
        save_settings()

    def _refresh_protection_status(self):
        if self.ignore_prot_var.get():
            self.protection_status.config(text="Protection: DISABLED (boss mode)", foreground="red")
        else:
            self.protection_status.config(text="Protection: ENABLED", foreground="green")

    def on_f5_taps_change(self, event=None):
            global F5_TAP_COUNT
            try:
                v = int(self.f5_taps_var.get())
                # sane bounds
                if v < 0:   v = 0
                if v > 50:  v = 50
                F5_TAP_COUNT = v
                self.f5_taps_status.config(text=f"Current: {F5_TAP_COUNT}", foreground="green")
                save_settings()
                print(f"[GUI] F5 tap count set to {F5_TAP_COUNT}")
            except ValueError:
                self.f5_taps_var.set(str(F5_TAP_COUNT))
                self.f5_taps_status.config(text=f"Must be integer. Kept: {F5_TAP_COUNT}", foreground="red")
                print("[GUI] F5 tap count must be an integer")

    def on_kills_per_home_change(self, event=None):
        global HOME_AFTER_KILLS_N
        try:
            v = int(self.kills_per_home_var.get())
            if v < 1:   v = 1
            if v > 999: v = 999
            HOME_AFTER_KILLS_N = v
            self.kills_per_home_status.config(text=f"Current: {HOME_AFTER_KILLS_N}", foreground="green")
            save_settings()
            print(f"[GUI] Home after N kills set to {HOME_AFTER_KILLS_N}")
        except Exception:
            # restore
            self.kills_per_home_var.set(str(int(globals().get("HOME_AFTER_KILLS_N", 1))))
            self.kills_per_home_status.config(
                text=f"Must be integer. Kept: {globals().get('HOME_AFTER_KILLS_N', 1)}",
                foreground="red"
            )
            print("[GUI] Home-after-kills must be an integer")

    def on_wander_timeout_change(self, event=None):
            """Validate and apply wander timeout before re-running Home."""
            global WANDER_TIMEOUT_S
            try:
                v = float(self.wander_timeout_var.get())
                # sane bounds (seconds)
                if v < 2.0:   v = 2.0
                if v > 300.0: v = 300.0
                WANDER_TIMEOUT_S = v
                self.wander_timeout_status.config(text=f"Current: {WANDER_TIMEOUT_S:.0f}s", foreground="green")
                save_settings()
                print(f"[GUI] Wander timeout set to {WANDER_TIMEOUT_S:.0f}s")
            except ValueError:
                self.wander_timeout_var.set(str(int(WANDER_TIMEOUT_S)))
                self.wander_timeout_status.config(text=f"Must be number. Kept: {int(WANDER_TIMEOUT_S)}s", foreground="red")
                print("[GUI] Wander timeout must be a number")

    def on_protection_toggle(self):
        """Toggle IGNORE_PROTECTION from checkbox and persist."""
        globals()["IGNORE_PROTECTION"] = self.ignore_prot_var.get()
        # NEW: keep AddressManager in sync too
        try:
            manager.set_ignore_protection(self.ignore_prot_var.get())
        except Exception:
            pass
        print(f"[GUI] Protection: {'DISABLED (boss mode)' if self.ignore_prot_var.get() else 'ENABLED'}")
        self._refresh_protection_status()
        try:
            save_settings()
        except Exception:
            pass

    def create_styles(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')

        # progress bars (ok)
        style.configure("red.Horizontal.TProgressbar", troughcolor='white', background='red')
        style.configure("blue.Horizontal.TProgressbar", troughcolor='white', background='blue')

        # ttk buttons: map background/foreground for states
        style.configure("success.TButton", foreground="white")
        style.map("success.TButton",
                background=[("!disabled", "#2e7d32"), ("active", "#1b5e20")])
        style.configure("danger.TButton", foreground="white")
        style.map("danger.TButton",
                background=[("!disabled", "#c62828"), ("active", "#8e0000")])
        
        # Custom button styles
        style.configure("success.TButton", background="green", foreground="white")
        style.configure("danger.TButton", background="red", foreground="white")

    def on_click_toggle(self):
        global CLICKING_ENABLED
        CLICKING_ENABLED = self.click_toggle_var.get()
        print(f"[TOGGLE] CLICKING_ENABLED = {CLICKING_ENABLED}")
        save_settings()

    def on_fast_click_toggle(self):
        global FAST_CLICK
        FAST_CLICK = self.fast_click_var.get()
        print(f"[TOGGLE] FAST_CLICK = {FAST_CLICK}")
        save_settings()

    def refresh_harvest_list(self):
        try:
            j, _p = load_walkable_json()
            nodes = j.get("harvest_nodes", [])
        except Exception as e:
            nodes = []
            print(f"[HARVEST][GUI] load failed: {e}")
        self.harv_list.delete(0, tk.END)
        for i, n in enumerate(nodes):
            x = n.get("x"); y = n.get("y"); t = n.get("type","click")
            face = n.get("facing","auto")
            hold = n.get("hold_seconds", (6.0 if t in ("mine","chop") else globals().get("LOOT_HOLD_SECONDS", 2.5)))
            self.harv_list.insert(tk.END, f"{i+1}. ({x},{y})  {t}  face={face}  hold={hold}")

    def on_harvest_add(self, *_):
        try:
            x = int(self.harv_x_var.get().strip())
            y = int(self.harv_y_var.get().strip())
            t = self.harv_type_var.get().strip().lower()
            if t not in ("click","mine","chop"):
                raise ValueError("type must be click/mine/chop")
        except Exception as e:
            print(f"[HARVEST][GUI] invalid input: {e}")
            return

        try:
            j, p = load_walkable_json()
            if "harvest_nodes" not in j or not isinstance(j["harvest_nodes"], list):
                j["harvest_nodes"] = []
            j["harvest_nodes"].append({"x": x, "y": y, "type": t})
            save_walkable_json(j, p)
            self.refresh_harvest_list()
            print(f"[HARVEST][GUI] Added node ({x},{y}) type={t}")
        except Exception as e:
            print(f"[HARVEST][GUI] add failed: {e}")

    def on_harvest_remove(self, *_):
        sel = self.harv_list.curselection()
        if not sel: return
        idx = sel[0]
        try:
            j, p = load_walkable_json()
            nodes = j.get("harvest_nodes", [])
            if 0 <= idx < len(nodes):
                removed = nodes.pop(idx)
                j["harvest_nodes"] = nodes
                save_walkable_json(j, p)
                self.refresh_harvest_list()
                print(f"[HARVEST][GUI] Removed {removed}")
        except Exception as e:
            print(f"[HARVEST][GUI] remove failed: {e}")

    def on_harvest_start(self, *_):
        ok = False
        try:
            ok = start_harvest_mode()
        except Exception as e:
            print(f"[HARVEST][GUI] start failed: {e}")
        if ok:
            self.harv_start.configure(state=tk.DISABLED)
            self.harv_stop.configure(state=tk.NORMAL)
        else:
            # refused because no nodes
            print("[HARVEST] No harvest nodes recorded for this map — not enabling.")

    def on_harvest_stop(self, *_):
        try:
            stop_harvest_mode()
        except Exception as e:
            print(f"[HARVEST][GUI] stop failed: {e}")
        finally:
            self.harv_start.configure(state=tk.NORMAL)
            self.harv_stop.configure(state=tk.DISABLED)

    # =============== Task Mode GUI Handlers ===============
    def refresh_task_list(self):
        """Refresh the task list display"""
        global _tasks
        try:
            _tasks = _load_tasks()
        except Exception as e:
            print(f"[TASK][GUI] load failed: {e}")
        self.task_list.delete(0, tk.END)
        for i, task in enumerate(_tasks):
            x = task.get("X", 0)
            y = task.get("Y", 0)
            action = task.get("Action", "Click")
            direction = task.get("Direction", "")
            click_coords = task.get("Click", (0, 0))
            display = f"{i+1}. ({x},{y}) {action}"
            if direction:
                display += f" dir={direction}"
            if action in ["Click", "DoubleClick", "RightClick"] and click_coords != (0, 0):
                if isinstance(click_coords, (list, tuple)) and len(click_coords) >= 2:
                    display += f" click=({click_coords[0]},{click_coords[1]})"
            self.task_list.insert(tk.END, display)

    def on_task_add(self, *_):
        """Add a new task"""
        global _tasks
        try:
            x = int(self.task_x_var.get().strip())
            y = int(self.task_y_var.get().strip())
            action = self.task_action_var.get().strip()
            direction = self.task_dir_var.get().strip()
        except Exception as e:
            print(f"[TASK][GUI] invalid input: {e}")
            return

        task = {"X": x, "Y": y, "Action": action, "Click": (0, 0)}
        if direction:
            task["Direction"] = direction
        
        # For click actions, prompt for click location
        if action in ["Click", "DoubleClick", "RightClick"]:
            self._record_click_for_new_task(task)
            return  # _record_click_for_new_task will add the task after recording
        
        _tasks.append(task)
        _save_tasks()
        self.refresh_task_list()
        print(f"[TASK][GUI] Added task ({x},{y}) action={action}")
    
    def on_task_add_at_current(self, *_):
        """Add task at current player location - uses current position AND direction"""
        global _tasks, pm, directional_address, x_address, y_address
        try:
            # Use direct memory reading (same as task system) to get accurate coordinates
            pos = _read_player_position_cerabot()
            if not pos:
                # Fallback to player_data_manager if direct read fails
                data = self.player_data_manager.get_data()
                x = int(data.get("x", 0))
                y = int(data.get("y", 0))
                if x == 0 and y == 0:
                    print("[TASK][GUI] ⚠️ Cannot read player position - coordinates are (0, 0). Make sure game is running and addresses are initialized.")
                    return
            else:
                x, y = pos
            
            # Read direction directly from memory to ensure accuracy
            direction_code = _read_player_direction_cerabot()
            if direction_code is None:
                # Fallback to player_data_manager if memory read failed
                data = self.player_data_manager.get_data()
                direction_code = int(data.get("direction", 0))
            
            # Convert direction code to name - use CURRENT direction
            # 0 = Down, 1 = Left, 2 = Up, 3 = Right
            direction_map = {0: "down", 1: "left", 2: "up", 3: "right"}
            direction = direction_map.get(direction_code, "down")
            action = self.task_action_var.get().strip()
            
            # Use current direction from memory/player data
            task = {"X": x, "Y": y, "Action": action, "Direction": direction, "Click": (0, 0)}
            
            # For click actions, prompt for click location
            if action in ["Click", "DoubleClick", "RightClick"]:
                self._record_click_for_new_task(task)
                return  # _record_click_for_new_task will add the task after recording
            
            _tasks.append(task)
            _save_tasks()
            self.refresh_task_list()
            print(f"[TASK][GUI] Added task at current location ({x},{y}) action={action} direction={direction} (code={direction_code})")
        except Exception as e:
            print(f"[TASK][GUI] Failed to add task at current location: {e}")
    
    def _record_click_for_new_task(self, task):
        """Record click position for a new task (before adding to list)"""
        import threading
        import pyautogui
        
        def capture_click():
            print("[TASK][GUI] Move mouse to click location and wait 3 seconds...")
            time.sleep(3)
            try:
                x, y = pyautogui.position()
                task["Click"] = (x, y)
                _tasks.append(task)
                _save_tasks()
                self.refresh_task_list()
                print(f"[TASK][GUI] Recorded click position ({x},{y}) and added task")
            except Exception as e:
                print(f"[TASK][GUI] Failed to record click: {e}")
                # Add task anyway with default click position
                _tasks.append(task)
                _save_tasks()
                self.refresh_task_list()
        
        threading.Thread(target=capture_click, daemon=True).start()
    
    def on_task_record_click(self, *_):
        """Record click position for selected task (allows changing click location)"""
        global _tasks
        sel = self.task_list.curselection()
        if not sel:
            print("[TASK][GUI] Please select a task first")
            return
        
        idx = sel[0]
        if not (0 <= idx < len(_tasks)):
            print(f"[TASK][GUI] Invalid task index: {idx}")
            return
        
        task = _tasks[idx]
        if task.get("Action") not in ["Click", "DoubleClick", "RightClick"]:
            print(f"[TASK][GUI] Task {idx+1} is not a click-type task (Action: {task.get('Action')})")
            return
        
        import threading
        import pyautogui
        
        def capture_click():
            print(f"[TASK][GUI] Move mouse to new click location for task {idx+1} and wait 3 seconds...")
            time.sleep(3)
            try:
                x, y = pyautogui.position()
                task["Click"] = (x, y)
                _save_tasks()
                self.refresh_task_list()
                print(f"[TASK][GUI] Recorded new click position ({x},{y}) for task {idx+1}")
            except Exception as e:
                print(f"[TASK][GUI] Failed to record click: {e}")
        
        threading.Thread(target=capture_click, daemon=True).start()
    
    def on_task_reset_clicks(self, *_):
        """Reset click locations - prompts to set new UP/RIGHT/DOWN/LEFT locations like CeraBot startup"""
        global _tasks
        import threading
        
        def record_direction_clicks():
            """Prompt user to click 4 times: Up, Right, Down, Left - like CeraBot startup"""
            print("[TASK][GUI] Click the following in your game window when prompted.")
            from pynput import mouse
            
            captured = []
            
            def capture_one(label):
                print(f"   ➜ Click the {label} spot now...")
                def on_click(x, y, button, pressed):
                    if pressed:
                        captured.append((x, y))
                        print(f"     {label} recorded at {(x, y)}")
                        return False
                with mouse.Listener(on_click=on_click) as listener:
                    listener.join()
            
            prompts = ["UP", "RIGHT", "DOWN", "LEFT"]
            for lab in prompts:
                capture_one(lab)
            
            # Store in order: [Up, Right, Down, Left]
            direction_clicks = captured[:4]  # Ensure we have exactly 4
            
            if len(direction_clicks) != 4:
                print(f"[TASK][GUI] Error: Expected 4 clicks, got {len(direction_clicks)}")
                return
            
            # Update all click-type tasks with direction-based click locations
            # Map direction names to indices: down=0, left=1, up=2, right=3
            direction_to_index = {"down": 2, "left": 3, "up": 0, "right": 1}
            updated_count = 0
            
            for task in _tasks:
                if task.get("Action") in ["Click", "DoubleClick", "RightClick"]:
                    direction = task.get("Direction", "down").lower()
                    index = direction_to_index.get(direction, 2)  # Default to down (index 2)
                    if 0 <= index < len(direction_clicks):
                        task["Click"] = direction_clicks[index]
                        updated_count += 1
                        print(f"[TASK][GUI] Updated task with direction '{direction}' -> click at {direction_clicks[index]}")
            
            if updated_count > 0:
                _save_tasks()
                self.refresh_task_list()
                print(f"[TASK][GUI] Updated {updated_count} tasks with new direction-based click locations")
                print(f"[TASK][GUI] Click points set (Up,Right,Down,Left): {direction_clicks}")
            else:
                print("[TASK][GUI] No click-type tasks to update")
        
        # Run in a separate thread so it doesn't block the GUI
        threading.Thread(target=record_direction_clicks, daemon=True).start()

    def on_task_remove(self, *_):
        """Remove selected task"""
        global _tasks
        sel = self.task_list.curselection()
        if not sel:
            return
        idx = sel[0]
        try:
            if 0 <= idx < len(_tasks):
                removed = _tasks.pop(idx)
                _save_tasks()
                self.refresh_task_list()
                print(f"[TASK][GUI] Removed task: {removed}")
        except Exception as e:
            print(f"[TASK][GUI] remove failed: {e}")

    def on_task_save(self, *_):
        """Save tasks to file"""
        global _tasks
        try:
            _save_tasks()
            print(f"[TASK][GUI] Saved {len(_tasks)} tasks")
        except Exception as e:
            print(f"[TASK][GUI] save failed: {e}")

    def on_task_start(self, *_):
        """Start task mode"""
        global _task_loops_remaining
        ok = False
        try:
            # Get loop count from GUI
            loops = int(self.task_loops_var.get())
            _task_loops_remaining = loops
            ok = start_task_mode()
        except Exception as e:
            print(f"[TASK][GUI] start failed: {e}")
        if ok:
            self.task_start.configure(state=tk.DISABLED)
            self.task_stop.configure(state=tk.NORMAL)
        else:
            print("[TASK] Failed to start task mode - check tasks and walkable tiles.")

    def on_task_stop(self, *_):
        """Stop task mode"""
        try:
            stop_task_mode()
        except Exception as e:
            print(f"[TASK][GUI] stop failed: {e}")
        finally:
            self.task_start.configure(state=tk.NORMAL)
            self.task_stop.configure(state=tk.DISABLED)

    def on_fast_click_params_change(self, event=None):
        """Validate and apply Fast Click burst size and gap."""
        global FAST_CLICK_BURST_COUNT, FAST_CLICK_GAP_S
        try:
            b = int(self.fast_click_burst_var.get())
            if b < 1: b = 1
            if b > 10: b = 10  # sane cap
            FAST_CLICK_BURST_COUNT = b
        except Exception:
            # reset UI to current
            self.fast_click_burst_var.set(str(FAST_CLICK_BURST_COUNT))

        try:
            g = float(self.fast_click_gap_var.get())
            if g < 0.02: g = 0.02
            if g > 1.0: g = 1.0
            FAST_CLICK_GAP_S = g
        except Exception:
            self.fast_click_gap_var.set(str(FAST_CLICK_GAP_S))

        print(f"[FAST_CLICK] burst={FAST_CLICK_BURST_COUNT} gap={FAST_CLICK_GAP_S:.3f}s")
        save_settings()

    def update_ui(self):
        # --- live player data ---
        data = self.player_data_manager.get_data()
        self.labels["X"].config(text=data["x"])
        self.labels["Y"].config(text=data["y"])
        self.labels["Direction"].config(text=data["direction"])

        # --- status labels / toggles that are safe to refresh ---
        self.flank_range_status.config(text=f"Current: {FLANK_RANGE}")
        self.click_toggle_var.set(CLICKING_ENABLED)
        self.fast_click_var.set(FAST_CLICK)

        # --- don't stomp the entries while user is editing them ---
        focused = self.root.focus_get()

        # Only refresh text if the corresponding Entry does NOT have focus
        if getattr(self, "fast_click_burst_entry", None) is None or focused is not self.fast_click_burst_entry:
            self.fast_click_burst_var.set(str(FAST_CLICK_BURST_COUNT))

        if getattr(self, "fast_click_gap_entry", None) is None or focused is not self.fast_click_gap_entry:
            self.fast_click_gap_var.set(str(FAST_CLICK_GAP_S))

        if getattr(self, "force_movement_entry", None) is None or focused is not self.force_movement_entry:
            self.force_movement_var.set(f"{float(FORCE_MOVEMENT_SECONDS):.4f}")

        self.force_movement_status.config(
            text=f"Current: {float(FORCE_MOVEMENT_SECONDS):.4f}s",
            foreground="blue"
        )

        # Update boss aggro status label
        if BOSS_AGGRO_TOGGLE:
            self.boss_aggro_status.config(text="Status: ENABLED", foreground="green")
        else:
            self.boss_aggro_status.config(text="Status: DISABLED", foreground="red")
        
        # Update sit timer status
        self.sit_timer_status.config(text=f"Current: {SIT_TIMER_SECONDS}s")
        
        # Update last moved timer status
        self.last_moved_timer_status.config(text=f"Current: {LAST_MOVED_TIMER_SECONDS}s")
        
        self.f5_taps_status.config(text=f"Current: {F5_TAP_COUNT}")

        self.wander_timeout_status.config(text=f"Current: {int(WANDER_TIMEOUT_S)}s")

        self.kills_per_home_status.config(text=f"Current: {HOME_AFTER_KILLS_N}")

        # Update bot status
        if bot_running:
            self.bot_status_label.config(text="Status: RUNNING", foreground="green")
            self.start_bot_button.config(state=tk.DISABLED)
            self.stop_bot_button.config(state=tk.NORMAL)
        else:
            self.bot_status_label.config(text="Status: STOPPED", foreground="red")
            self.start_bot_button.config(state=tk.NORMAL)
            self.stop_bot_button.config(state=tk.DISABLED)
        
        # Update task mode status
        if TASK_MODE:
            self.task_start.config(state=tk.DISABLED)
            self.task_stop.config(state=tk.NORMAL)
        else:
            self.task_start.config(state=tk.NORMAL)
            self.task_stop.config(state=tk.DISABLED)
        
        # Update home status
        self.home_status.config(text=f"Current: ({HOME_POS[0]}, {HOME_POS[1]})")
             
        self.draw_map()
        self.root.after(100, self.update_ui)

        # --- Update chat list from recent_speech_log ---
        try:
            self.chat_list.delete(0, tk.END)
            # show last 30 entries (or fewer)
            for ts, addr, text in list(recent_speech_log)[-30:]:
                hh = time.strftime("%H:%M:%S", time.localtime(ts))
                who = (addr[-6:] if addr else "??")
                self.chat_list.insert(tk.END, f"{hh} [{who}] {text[:70]}")
            if recent_speech_log:
                ts, addr, text = recent_speech_log[-1]
                self.last_speech_lbl.config(text=f"Last: {text[:80]}")
            else:
                self.last_speech_lbl.config(text="Last: ")
        except Exception:
            pass

        # ==================== UPDATE PLAYER STATS ====================
        stats = read_all_stats()
        if stats:
            for key, val in stats.items():
                if key in self.stats_labels:
                    self.stats_labels[key].config(text=str(val if val is not None else "N/A"))

    def draw_map(self):
        # wipe previous frame
        self.canvas.delete("all")

        # canvas + grid geometry
        canvas_size = 260   # matches v7 Map View canvas
        max_x = 20          # visible tiles in each axis (tweak if you like)
        max_y = 20
        cell_w = canvas_size / max_x
        cell_h = canvas_size / max_y

        # background + grid
        self.canvas.create_rectangle(0, 0, canvas_size, canvas_size, fill="gray", outline="")
        for i in range(max_x + 1):
            x = i * cell_w
            self.canvas.create_line(x, 0, x, canvas_size, fill="black")
        for j in range(max_y + 1):
            y = j * cell_h
            self.canvas.create_line(0, y, canvas_size, y, fill="black")

        # player & NPCs
        data = self.player_data_manager.get_data()
        px, py = data["x"], data["y"]

        cx = canvas_size / 2
        cy = canvas_size / 2

        # player at center
        r = 6
        self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r, fill="orange", outline="black")

        # plot NPCs relative to player
        try:
            for item in map_data:
                if item.get("type") != "npc":
                    continue
                nx, ny = item["X"], item["Y"]
                sx = cx + (nx - px) * cell_w
                sy = cy + (ny - py) * cell_h
                self.canvas.create_oval(sx - 3, sy - 3, sx + 3, sy + 3, fill="red", outline="black")
        except Exception:
            pass

    def run(self):
        self.root.mainloop()

    def on_boss_aggro_toggle(self):
        """Handle boss aggro toggle changes"""
        global BOSS_AGGRO_TOGGLE
        BOSS_AGGRO_TOGGLE = self.boss_aggro_var.get()
        
        # Update status label
        if BOSS_AGGRO_TOGGLE:
            self.boss_aggro_status.config(text="Status: ENABLED", foreground="green")
        else:
            self.boss_aggro_status.config(text="Status: DISABLED", foreground="red")
        
        print(f"[GUI] Is Boss aggro?: {'ENABLED' if BOSS_AGGRO_TOGGLE else 'DISABLED'}")
        
        # Save settings after change
        save_settings()

    def on_flank_range_change(self, event=None):
        """Validate and apply FLANK_RANGE changes from the GUI, then persist settings."""
        global FLANK_RANGE
        try:
            val = int(self.flank_range_var.get())
            if 1 <= val <= 5:  # tweak max if you like
                FLANK_RANGE = val
                self.flank_range_status.config(text=f"Current: {FLANK_RANGE}", foreground="green")
                print(f"[GUI] Flank range set to {FLANK_RANGE}")
                save_settings()
            else:
                self.flank_range_var.set(str(FLANK_RANGE))
                self.flank_range_status.config(text=f"Must be 1–5. Kept: {FLANK_RANGE}", foreground="red")
        except ValueError:
            self.flank_range_var.set(str(FLANK_RANGE))
            self.flank_range_status.config(text=f"Must be integer. Kept: {FLANK_RANGE}", foreground="red")

    def on_start_bot(self):
        """Handle start bot button click"""
        global bot_running
        start_bot()
        self.start_bot_button.config(state=tk.DISABLED)
        self.stop_bot_button.config(state=tk.NORMAL)
        self.bot_status_label.config(text="Status: RUNNING", foreground="green")
        print("[GUI] Bot started")

    def on_stop_bot(self):
        """Handle stop bot button click"""
        global bot_running
        stop_bot()
        self.start_bot_button.config(state=tk.NORMAL)
        self.stop_bot_button.config(state=tk.DISABLED)
        self.bot_status_label.config(text="Status: STOPPED", foreground="red")
        print("[GUI] Bot stopped")

    def on_last_moved_timer_change(self, event):
        """Handle changes to the last moved timer configuration."""
        global LAST_MOVED_TIMER_SECONDS
        try:
            new_value = int(self.last_moved_timer_var.get())
            if new_value > 0 and new_value <= 300:  # Reasonable range: 1-300 seconds
                LAST_MOVED_TIMER_SECONDS = new_value
                self.last_moved_timer_status.config(text=f"Current: {LAST_MOVED_TIMER_SECONDS}s", foreground="green")
                print(f"[GUI] Last moved timer set to {LAST_MOVED_TIMER_SECONDS}s")
                # Save settings after successful change
                save_settings()
            elif new_value > 300:
                self.last_moved_timer_var.set(str(LAST_MOVED_TIMER_SECONDS))
                self.last_moved_timer_status.config(text=f"Max 300s allowed. Reset to {LAST_MOVED_TIMER_SECONDS}s", foreground="red")
                print(f"[GUI] Last moved timer too high (max 300s). Reset to {LAST_MOVED_TIMER_SECONDS}s")
            else:
                self.last_moved_timer_var.set(str(LAST_MOVED_TIMER_SECONDS))
                self.last_moved_timer_status.config(text=f"Must be positive. Reset to {LAST_MOVED_TIMER_SECONDS}s", foreground="red")
                print(f"[GUI] Last moved timer must be positive. Reset to {LAST_MOVED_TIMER_SECONDS}s")
        except ValueError:
            self.last_moved_timer_var.set(str(LAST_MOVED_TIMER_SECONDS))
            self.last_moved_timer_status.config(text=f"Must be integer. Reset to {LAST_MOVED_TIMER_SECONDS}s", foreground="red")
            print(f"[GUI] Last moved timer must be an integer. Reset to {LAST_MOVED_TIMER_SECONDS}s")

    def on_sit_timer_change(self, event):
        """Handle changes to the sit timer configuration."""
        global SIT_TIMER_SECONDS
        try:
            new_value = int(self.sit_timer_var.get())
            if new_value > 0 and new_value <= 300:  # Reasonable range: 1-300 seconds
                SIT_TIMER_SECONDS = new_value
                self.sit_timer_status.config(text=f"Current: {SIT_TIMER_SECONDS}s", foreground="green")
                print(f"[GUI] Sit timer set to {SIT_TIMER_SECONDS}s")
                # Save settings after successful change
                save_settings()
            elif new_value > 300:
                self.sit_timer_var.set(str(SIT_TIMER_SECONDS))
                self.sit_timer_status.config(text=f"Max 300s allowed. Reset to {SIT_TIMER_SECONDS}s", foreground="red")
                print(f"[GUI] Sit timer too high (max 300s). Reset to {SIT_TIMER_SECONDS}s")
            else:
                self.sit_timer_var.set(str(SIT_TIMER_SECONDS))
                self.sit_timer_status.config(text=f"Must be positive. Reset to {SIT_TIMER_SECONDS}s", foreground="red")
                print(f"[GUI] Sit timer must be positive. Reset to {SIT_TIMER_SECONDS}s")
        except ValueError:
            self.sit_timer_var.set(str(SIT_TIMER_SECONDS))
            self.sit_timer_status.config(text=f"Must be integer. Reset to {SIT_TIMER_SECONDS}s", foreground="red")
            print(f"[GUI] Sit timer must be an integer. Reset to {SIT_TIMER_SECONDS}s")

    def on_force_movement_change(self, event=None):
        """Handle updates to the force movement hold duration."""
        global FORCE_MOVEMENT_SECONDS
        try:
            new_value = float(self.force_movement_var.get())
            if 0.5 <= new_value <= 10.0:
                FORCE_MOVEMENT_SECONDS = new_value
                self.force_movement_status.config(
                    text=f"Current: {FORCE_MOVEMENT_SECONDS:.3f}s",
                    foreground="green"
                )
                # Keep the entry formatted with four decimals
                self.force_movement_var.set(f"{FORCE_MOVEMENT_SECONDS:.4f}")
                print(f"[GUI] Force movement hold set to {FORCE_MOVEMENT_SECONDS:.4f}s")
                save_settings()
            else:
                raise ValueError("out_of_range")
        except Exception:
            # Revert to the stored value
            self.force_movement_var.set(f"{float(FORCE_MOVEMENT_SECONDS):.4f}")
            self.force_movement_status.config(
                text=f"Allowed range 0.5–10.0s. Reset to {float(FORCE_MOVEMENT_SECONDS):.4f}s",
                foreground="red"
            )
            print("[GUI] Force movement hold must be between 0.5 and 10.0 seconds.")

    def on_combat_timer_change(self, event=None):
        """Handle changes to the combat task timer configuration."""
        global COMBAT_TASK_DURATION
        try:
            new_value = int(self.combat_timer_var.get())
            if new_value < 0:
                raise ValueError("negative")
            COMBAT_TASK_DURATION = new_value
            print(f"[GUI] Combat task timer set to {COMBAT_TASK_DURATION}s")
            save_settings()
        except Exception:
            self.combat_timer_var.set(str(COMBAT_TASK_DURATION))
            print("[GUI] Combat task timer must be a non-negative integer.")

    def add_npc_target(self, event=None):
        """Adds a new NPC ID to the target list."""
        npc_id = self.add_npc_var.get().strip()
        if npc_id:
            try:
                npc_id_int = int(npc_id)
                if npc_id_int not in MOB_ID_FILTERS:
                    MOB_ID_FILTERS.add(npc_id_int)
                    # immediate UI feedback (update_ui also refreshes it)
                    targets_text = ", ".join(map(str, sorted(MOB_ID_FILTERS)))
                    if hasattr(self, "targets_display"):
                        self.targets_display.config(text=targets_text, foreground="green")
                    print(f"[GUI] Added NPC ID {npc_id_int} to targets.")
                    save_settings()
                else:
                    print(f"[GUI] NPC ID {npc_id_int} is already in the target list.")
            except ValueError:
                print(f"[GUI] Invalid NPC ID format: {npc_id}")
        self.add_npc_var.set("")

    def remove_npc_target(self, event=None):
        """Removes an NPC ID from the target list."""
        npc_id = self.remove_npc_var.get().strip()
        if npc_id:
            try:
                npc_id_int = int(npc_id)
                if npc_id_int in MOB_ID_FILTERS:
                    MOB_ID_FILTERS.remove(npc_id_int)
                    targets_text = ", ".join(map(str, sorted(MOB_ID_FILTERS)))
                    if targets_text:
                        if hasattr(self, "targets_display"):
                            self.targets_display.config(text=targets_text, foreground="green")
                    else:
                        self.targets_display.config(text="No targets set", foreground="red")
                    print(f"[GUI] Removed NPC ID {npc_id_int} from targets.")
                    save_settings()
                else:
                    print(f"[GUI] NPC ID {npc_id_int} not found in the target list.")
            except ValueError:
                print(f"[GUI] Invalid NPC ID format: {npc_id}")
        self.remove_npc_var.set("")

    def on_closing(self):
        """Saves settings and exits the GUI."""
        save_settings()
        self.root.destroy()

    def on_home_change(self, event=None):
        """Validate and apply HOME_POS changes from the GUI, then persist settings."""
        global HOME_POS
        x_str = self.home_x_var.get().strip()
        y_str = self.home_y_var.get().strip()
        try:
            new_x = int(x_str)
            new_y = int(y_str)
            HOME_POS = (new_x, new_y)
            self.home_status.config(text=f"Current: ({HOME_POS[0]}, {HOME_POS[1]})", foreground="green")
            print(f"[GUI] Home location set to {HOME_POS}")
            save_settings()
        except ValueError:
            # Revert fields to current HOME_POS
            self.home_x_var.set(str(HOME_POS[0]))
            self.home_y_var.set(str(HOME_POS[1]))
            self.home_status.config(text=f"Invalid input. Current: ({HOME_POS[0]}, {HOME_POS[1]})", foreground="red")
            print("[GUI] Invalid home location; must be integers.")

    def set_home_from_current(self):
        """Set HOME_POS from the current player position via player_data_manager."""
        global HOME_POS
        try:
            data = self.player_data_manager.get_data()
            new_x = int(data.get("x", HOME_POS[0]))
            new_y = int(data.get("y", HOME_POS[1]))
            HOME_POS = (new_x, new_y)
            # Reflect in fields and status
            self.home_x_var.set(str(new_x))
            self.home_y_var.set(str(new_y))
            self.home_status.config(text=f"Current: ({HOME_POS[0]}, {HOME_POS[1]})", foreground="green")
            print(f"[GUI] Home location set from current position: {HOME_POS}")
            save_settings()
        except Exception as e:
            self.home_status.config(text=f"Failed to set from current pos. Current: ({HOME_POS[0]}, {HOME_POS[1]})", foreground="red")
            print(f"[GUI] Failed to set home from current pos: {e}")

    

def check_player_data(x_address, y_address, directional_address):
    """
    Builds the per-tick snapshot for player + NPCs.

    Priority:
      1) NOT IN LIVE  -> instant removal (authoritative)
      2) EXP (handled elsewhere)
      3) COORDS       -> publish only for live, in-bounds entities

    Never ghost-publishes. If an NPC isn't live this tick, it is removed and not appended.

    Expects globals:
      pm, manager, player_data_manager, map_data, bot_running,
      initialize_pymem, INVALID_COORD_LIMIT, MOB_ID_OFFSET, SPAWN_UID_OFFSET,
      RESPAWN_CHANGE_SEC, LAST_MOVED_TIMER_SECONDS
    Side-channel:
      RECENT_REMOVALS[addr_hex] = (reason:str, ts:float)
    """
    import time

    FUNC = "check_player_data"
    COORD_FORGIVE_FRAMES = 0  # set 0 to disable coordinate forgiveness
    OOB_STRIKES_DEFAULT = 0   # persistent OOB without a last_good_xy -> toss
    OOB_STRIKES_TARGET = 0    # stricter for current target

    # ---- side-channel for diagnostics (read by monitor) ----
    if "RECENT_REMOVALS" not in globals():
        globals()["RECENT_REMOVALS"] = {}
    RECENT_REMOVALS = globals()["RECENT_REMOVALS"]

    def _log(msg):
        print(f"[{FUNC}][{time.strftime('%H:%M:%S')}] {msg}")

    def _coords_oob(xv: int, yv: int) -> bool:
        return (
            xv is None or yv is None or
            xv <= 0 or yv <= 0 or
            xv > INVALID_COORD_LIMIT or yv > INVALID_COORD_LIMIT
        )

    def _ids_look_valid(uid: int, suid: int) -> bool:
        # Adjust sentinels if your game differs.
        return not (uid in (0, -1, 0xFFFF) or suid in (0, -1, 0xFFFF))

    def _instant_not_in_live_remove(addr_hex: str, now: float, reason: str = "not in live"):
        RECENT_REMOVALS[addr_hex] = (reason, now)
        print(f"[REMOVE] {addr_hex} -> {reason}")

        try:
            if addr_hex == globals().get("current_target_npc"):
                # skip if we just killed this addr (EXP hook or otherwise)
                last_k = RECENTLY_KILLED.get(addr_hex, 0.0)
                if (time.monotonic() - last_k) >= KILL_QUARANTINE_SEC and not _in_immunity(addr_hex):
                    _fire_kill_once(addr_hex, reason=reason.upper())
        except Exception:
            pass

        try:
            manager.remove_address(addr_hex)
        except Exception as e:
            _log(f"REMOVE_ERR({reason}): {addr_hex} | {e}")


    # ---------- Authoritative pre-pass ----------
    # Return a dict of addr_hex -> (x, y, uid, suid)
    def _build_live_info():
        live_info = {}
        for addr_hex, meta in list(manager.addresses.items()):
            try:
                ax = int(addr_hex, 16)
                ay = int(meta["paired_address"], 16)

                x = pm.read_short(ax)
                y = pm.read_short(ay)
                uid  = pm.read_short(ax - MOB_ID_OFFSET)
                suid = pm.read_short(ax - SPAWN_UID_OFFSET)

                if not _ids_look_valid(uid, suid):
                    continue
                if _coords_oob(x, y):
                    continue

                live_info[addr_hex] = (x, y, uid, suid)
            except Exception:
                # any read failure -> not live in this pre-pass
                continue
        return live_info

    global pm
    initialize_pymem()

    try:
        while True:
            if not bot_running:
                time.sleep(0.1)
                continue

            try:
                px = pm.read_short(x_address)
                py = pm.read_short(y_address)

                raw_dir = pm.read_bytes(directional_address, 1)[0]

                # Adjust if your client encodes differently.
                # Assumes: 0 = Down, 1 = Left, 2 = Up, 3 = Right
                DIR_MAP = {
                    0: 0,  # raw 0 -> Down
                    1: 1,  # raw 1 -> Left
                    2: 2,  # raw 2 -> Up
                    3: 3,  # raw 3 -> Right
                }

                # IMPORTANT: keep the variable name *direction* so the rest of the code works.
                direction = DIR_MAP.get(raw_dir, raw_dir)

                # (optional while testing)
                # print(f"[dir] raw={raw_dir} -> mapped={direction}")

                player_data_manager.update(px, py, direction)

                # --- authoritative live snapshot (pre-pass) ---
                live_info = _build_live_info()
                live_addrs = set(live_info.keys())

                # Build a fresh frame starting with player
                next_frame = [{
                    "type": "player",
                    "X": px,
                    "Y": py,
                    "direction": direction,
                }]

                now = time.time()

                # After this, only iterate addresses that are confirmed live:
                for addr_hex in list(live_addrs):
                    meta = manager.addresses.get(addr_hex)
                    if meta is None:
                        # could have been removed above
                        continue

                    # We already have a good read from the pre-pass
                    x, y, uid, suid = live_info[addr_hex]

                    # UNIQUE-ID / SPAWN-UID FLIP (respawn => old mob died)
                    last_uid  = meta.get("last_unique_id")
                    last_suid = meta.get("last_spawn_uid")

                    if last_uid is None and last_suid is None:
                        meta["last_unique_id"] = uid
                        meta["last_spawn_uid"] = suid
                    elif uid != last_uid or suid != last_suid:
                        _instant_not_in_live_remove(addr_hex, now, reason=f"| suid {last_suid}")
                        continue
                    else:
                        meta["last_unique_id"] = uid
                        meta["last_spawn_uid"] = suid

                    # --- POST-PROTECT SUID SHIFT GUARD  [NEW] ---
                    pc = meta.get("protected_cleared_at")
                    snap_suid = meta.get("suid_at_protect")
                    if pc and (snap_suid is not None) and (suid != snap_suid):
                        _instant_not_in_live_remove(addr_hex, now, reason="protect_suid_shift")
                        continue

                    # Housekeeping fields (for optional OOB forgiveness)
                    meta.setdefault("first_seen_ts", now)
                    meta.setdefault("oob_strikes", 0)
                    meta.setdefault("last_good_xy", None)
                    meta.setdefault("forgive_left", COORD_FORGIVE_FRAMES)

                    use_x, use_y = x, y

                    # Read NPC's "got_hit" counter and protect when it increments due to someone else.
                    prev_got_hit = meta.get("got_hit")
                    try:
                        got_hit = pm.read_int(int(addr_hex, 16) + 0x1D0)  # same offset as 5.3
                    except Exception:
                        got_hit = prev_got_hit  # keep prior if unreadable

                    meta["got_hit"] = got_hit

                    # If counter rises and it wasn't *our* swing, protect for 8s
                    if (
                        isinstance(got_hit, int) and isinstance(prev_got_hit, int) and got_hit > prev_got_hit
                    ):
                        # Treat "recently me" as: I'm holding/just held CTRL on this exact target.
                        from time import time as _now
                        me_recent = recently_attacking(addr_hex, window=0.40)  # a hair longer than 0.30
                        if not me_recent and not manager.ignore_protection:
                            # ... inside the GOT-HIT block (you already have uid, suid in scope here)
                            manager.mark_protected(
                                addr_hex,
                                seconds=3,
                                reason="got_hit",
                                meta={"delta": got_hit - prev_got_hit, "uid_at_protect": uid, "suid_at_protect": suid}  # NEW
                            )
                            meta["uid_at_protect"] = uid      
                            meta["suid_at_protect"] = suid  


                    # Movement freshness (for stale cleanup elsewhere)
                    lx, ly = meta.get("last_x"), meta.get("last_y")
                    if (lx != use_x) or (ly != use_y):
                        meta["last_x"] = use_x
                        meta["last_y"] = use_y
                        meta["last_moved"] = now
                    else:
                        # Ensure last_moved exists for stale sweeps
                        meta.setdefault("last_moved", now)

                    # Append (never ghost-publish)
                    next_frame.append({
                        "type": "npc",
                        "X": use_x,
                        "Y": use_y,
                        "unique_id": uid,
                        "spawn_uid": suid,
                        "address_x": addr_hex,
                        "address_y": meta["paired_address"],
                    })

                # publish atomically
                map_data[:] = next_frame

            except Exception as e:
                _log(f"tick error: {e}")

            time.sleep(0.1)

    except Exception as e:
        _log(f"failed to initialize: {e}")


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        action = payload.get('action')
        address = payload.get('address')
        if action == 'add' and address is not None:
            manager.add_address(address)

def start_frida(npc_address):
    print("Npc Started")
    frida_script = f"""
Interceptor.attach(Module.findBaseAddress("Endless.exe").add({npc_address}), {{
    onEnter: function(args) {{
        var eax = this.context.eax.toInt32();
        var offset = {varOffset};
        var address = eax + offset;
        var addressHex = '0x' + address.toString(16).toUpperCase();
        send({{action: 'add', address: addressHex}});
    }}
}});
"""
    session = frida.attach("Endless.exe")
    script = session.create_script(frida_script)
    script.on('message', on_message)
    script.load()

def _pick_point_from_direction(points, facing: int):
    """
    Returns exactly one (x,y) from the 4 saved points based on facing.
    Expected order of `points`: [Up, Right, Down, Left].
    """
    pts = list(points)[:4]
    if len(pts) < 4:
        print("[LOOT] Need 4 resurrect points (Up,Right,Down,Left).")
        return None
    slot = DIR_TO_SLOT.get(int(facing), 0)
    return pts[slot]

def _do_clicks(game_win, points, tag="CLICK"):
    """
    Bring the game window to front, then perform exactly 4 corpse/loot clicks.

    IMPORTANT:
    - If CLICKING_ENABLED is False, do NOTHING (no flags, no sleep, no prints).
    - Only gate other threads (clicks_in_progress) when we are actually clicking.
    """
    # Early-out: clicking disabled = no-op (keeps retarget instant)
    if not globals().get("CLICKING_ENABLED", True):
        return

    # --- lazy imports so this stays self-contained ---
    try:
        import time
        import pydirectinput
    except Exception:
        pass

    # --- globals / shared flags ---
    global clicks_in_progress
    try:
        clicks_in_progress  # threading.Event set elsewhere
    except NameError:
        import threading
        clicks_in_progress = threading.Event()

    # Normalize points: require 4, ignore extras
    pts = list(points)[:4]
    if len(pts) < 4:
        print(f"[WARN] only {len(pts)} saved points — skipping {tag} clicks")
        return

    # Enter busy section so other routines wait on us (only when actually clicking)
    clicks_in_progress.set()
    try:
        # Best-effort: pause movement and ensure no attack is held
        try:
            _pause_movement()
        except Exception:
            try:
                movement_allowed.clear()
            except Exception:
                pass
        try:
            release_key('ctrl')
        except Exception:
            pass

        # Focus game window so clicks land
        if game_win:
            try:
                game_win.activate()
                time.sleep(0.20)
            except Exception:
                pass

        # --- enabled path: perform four click locations ---
        total = len(pts)  # should be 4
        for idx, (x, y) in enumerate(pts, start=1):
            print(f"[{tag}] clicking point {idx}/{total} at ({x},{y})")
            try:
                # Triple-click with small spacing to ensure pickup
                pydirectinput.click(x=x, y=y)
                time.sleep(0.15)
                pydirectinput.click(x=x, y=y)
                time.sleep(0.15)
                pydirectinput.click(x=x, y=y)
            except Exception as e:
                print(f"[{tag}] click {idx} failed: {e}")
            # Small move-between-points delay
            time.sleep(0.30)

        # Final settle so last click registers
        time.sleep(0.15)

    finally:
        # Best-effort resume movement
        try:
            _resume_movement()
        except Exception:
            try:
                movement_allowed.set()
            except Exception:
                pass
        # Always clear busy flag
        clicks_in_progress.clear()

def _do_directional_loot(game_win, points, facing, hold_seconds=6.0, tag="D-LOOT"):
    """
    If CLICKING_ENABLED is False: return immediately (no flags, no sleeps, no prints).

    If CLICKING_ENABLED is True:
      - When FAST_CLICK is True: perform a fast 3x burst on the directional point and return.
      - Otherwise: hold-click the point for `hold_seconds` like before.
    """
    # Early-out: clicking disabled = no-op (keeps retarget instant)
    if not globals().get("CLICKING_ENABLED", True):
        return

    # --- lazy imports to keep this self-contained ---
    try:
        import time as _t
        import pydirectinput
    except Exception:
        pass

    # Choose the target point based on facing
    target = _pick_point_from_direction(points, facing)
    if not target:
        return
    x, y = target

    # --- shared flags ---
    global clicks_in_progress
    try:
        clicks_in_progress
    except NameError:
        import threading
        clicks_in_progress = threading.Event()

    clicks_in_progress.set()
    try:
        # Pause movement & release attack
        try:
            _pause_movement()
        except Exception:
            try: movement_allowed.clear()
            except Exception: pass
        try:
            release_key('ctrl')
        except Exception:
            pass

        # Focus game window (best-effort)
        if game_win:
            try:
                game_win.activate()
                _t.sleep(0.20)
            except Exception:
                pass

        # === FAST BURST PATH ===
        if globals().get("FAST_CLICK", False):
            print(f"[{tag}] FAST_CLICK enabled: burst {FAST_CLICK_BURST_COUNT} at ({x},{y})")
            for i in range(int(globals().get("FAST_CLICK_BURST_COUNT", 3))):
                try:
                    pydirectinput.click(x=x, y=y)
                except Exception as e:
                    print(f"[{tag}] burst click err: {e}")
                _t.sleep(float(globals().get("FAST_CLICK_GAP_S", 0.12)))
            # tiny settle
            _t.sleep(0.05)
            return

        # === NORMAL HOLD PATH (unchanged behavior) ===
        t0 = _t.monotonic()
        print(f"[{tag}] Let me Rob This Niggas Pockets Real Quick!")
        while (_t.monotonic() - t0) < float(hold_seconds):
            try:
                pydirectinput.click(x=x, y=y)
            except Exception as e:
                print(f"[{tag}] click err: {e}")
            _t.sleep(0.12)

        _t.sleep(0.05)

    finally:
        # Resume movement
        try:
            _resume_movement()
        except Exception:
            try: movement_allowed.set()
            except Exception: pass
        clicks_in_progress.clear()

def _do_fast_click_burst(game_win, pts, facing, burst, gap, tag="KILL"):
    """
    Clicks the directional loot point 'burst' times with 'gap' seconds between clicks.
    Uses clicks_in_progress to gate other routines similar to the hold-click logic.
    """
    import time
    try:
        clicks_in_progress.set()
    except Exception:
        pass

    try:
        if not pts:
            return

        # choose directional slot, fallback to index 0 if missing
        try:
            slot = DIR_TO_SLOT.get(int(facing) % 4, 0)
        except Exception:
            slot = 0
        if slot < 0 or slot >= len(pts):
            slot = 0

        x, y = pts[slot]

        # focus game window if present
        try:
            if game_win:
                game_win.activate()
                time.sleep(0.05)
        except Exception:
            pass

        # do the clicks
        for _ in range(int(burst)):
            try:
                pyautogui.click(x=x, y=y)
            except Exception:
                pass
            time.sleep(float(gap))

    finally:
        try:
            clicks_in_progress.clear()
        except Exception:
            pass

def load_walkable_tiles(file_path: str | None = None):
    """
    Loads walkable tiles from JSON, robust across platforms and launch methods.
    - Accepts optional file_path (absolute or relative).
    - If relative, or not given, we resolve via _resolve_walkable_path.
    - Falls back to a 101x101 grid if not found or invalid.
    """
    # If caller passed a path, prefer it; otherwise use CLI/env/script-dir/CWD search
    path: Path | None
    if file_path:
        p = Path(os.path.expandvars(os.path.expanduser(file_path)))
        path = p if p.is_absolute() else (Path(__file__).resolve().parent / p)
        path = path.resolve()
    else:
        path = _resolve_walkable_path(WALKABLE_ARG)

    # Try to load
    try:
        if path is None:
            raise FileNotFoundError("walkable.json not found by resolver")

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        tiles = data.get("safe_tiles") or []
        if tiles:
            return {(int(t["X"]), int(t["Y"])) for t in tiles}

        print(f"[WALKABLE] No tiles in {path}; using default grid.")
    except Exception as e:
        msg = f"{e.__class__.__name__}: {e}"
        print(f"[WALKABLE] Error loading tiles ({msg}). Using default grid.")

    # Fallback: 0..100 inclusive
    return {(x, y) for x in range(101) for y in range(101)}

def heuristic(a, b):
    return abs(a[0] - b[0]) + abs(a[1] - b[1])

def astar_pathfinding(start, goal, walkable_tiles):
    open_set = PriorityQueue()
    open_set.put((0, start))
    came_from = {}
    g_score = {start: 0}
    f_score = {start: heuristic(start, goal)}
    while not open_set.empty():
        _, current = open_set.get()
        if current == goal:
            path = []
            while current in came_from:
                path.append(current)
                current = came_from[current]
            path.append(start)
            path.reverse()
            return path
        for dx, dy in [(0, 1), (1, 0), (0, -1), (-1, 0)]:
            neighbor = (current[0] + dx, current[1] + dy)
            if neighbor in walkable_tiles:
                tentative_g_score = g_score[current] + 1
                if neighbor not in g_score or tentative_g_score < g_score[neighbor]:
                    came_from[neighbor] = current
                    g_score[neighbor] = tentative_g_score
                    f_score[neighbor] = tentative_g_score + heuristic(neighbor, goal)
                    open_set.put((f_score[neighbor], neighbor))
    return None

def find_closest_npc(player_x, player_y, npcs):
    closest_npc = None
    min_distance = float('inf')
    for npc in npcs:
        distance = abs(player_x - npc['X']) + abs(player_y - npc['Y'])
        if distance < min_distance:
            min_distance = distance
            closest_npc = npc
    return closest_npc

def _is_target_stale(addr, now=None):
    """Return True if the target hasn't moved for LAST_MOVED_TIMER_SECONDS."""
    try:
        meta = manager.addresses.get(addr)
        if not meta:
            return False
        if now is None:
            now = time.time()
        last = meta.get("last_moved") or meta.get("first_seen_ts") or now
        return (now - last) >= LAST_MOVED_TIMER_SECONDS
    except Exception:
        return False

def key_listener():
    global pause_flag
    import keyboard
    while True:
        # Check if bot should be running
        if not bot_running:
            time.sleep(0.1)
            continue
            
        if keyboard.is_pressed(','):
            pause_flag = True
            print("Pausing for 1 minute...")
            time.sleep(60)
            pause_flag = False
            print("Resuming combat...")
        time.sleep(0.1)

last_combat_time = time.time()
sitting = False

def combat_thread():
    """
    EXP-less combat loop:
      - Picks the closest valid NPC (filtered by MOB_ID_FILTERS and walkable tiles).
      - If adjacent with clear LOS -> face + hold CTRL to attack.
      - Otherwise path toward an adjacent flank tile next to the NPC.
      - If target disappears, immediately yield so loot/home can run (no stepping first).
      - Smart wandering when no valid NPCs are present.
    """
    import time, random
    from collections import deque
    global last_combat_time, sitting, pause_flag, current_target_npc, movement_allowed, _target_immunity_until, IMMUNITY_SEC, speech_quarantine_until, last_attack_time, last_attack_addr

    # Ensure globals exist
    try:
        _ = _target_immunity_until
    except NameError:
        _target_immunity_until = {}
    try:
        _ = IMMUNITY_SEC
    except NameError:
        IMMUNITY_SEC = 5.0

    # Walkable ground: load from your map or fall back to a simple grid
    base_walkable = set(load_walkable_tiles() or [])
    if not base_walkable:
        base_walkable = {(x, y) for x in range(101) for y in range(101)}
    
    last_direction = None
    wandering_target = None
    stuck_timer_start = None
    last_position = None
    ctrl_pressed = False
    ctrl_pressed_since = 0.0 
    CTRL_MISALIGN_TIMEOUT = 0.60
    blocked_tiles = {}         # (x, y) -> expiry_time
    movement_start_time = None
    target_tile = None
    _wander_since = None
    target_move_info = {}
    _npc_ignore_until = {}

    # --- ATTACK HELPERS: centralize CTRL + protection toggling ---
    def _begin_attack(target_addr):
        """
        Start attacking: hold CTRL, tell manager to ignore protection,
        and stamp last_attack_* for 'my hit' detection elsewhere.
        """
        nonlocal ctrl_pressed, ctrl_pressed_since
        global last_attack_time, last_attack_addr
        try:
            manager.set_ignore_protection(True)
        except Exception:
            pass
        hold_key('ctrl')
        ctrl_pressed = True
        ctrl_pressed_since = time.time()
        last_attack_time = ctrl_pressed_since
        last_attack_addr = target_addr

    def _end_attack():
        """
        Stop attacking: release CTRL if needed and restore protection handling.
        Safe to call even if we aren't currently holding CTRL.
        """
        nonlocal ctrl_pressed, ctrl_pressed_since
        if ctrl_pressed:
            try:
                release_key('ctrl')
            except Exception:
                pass
            ctrl_pressed = False
            ctrl_pressed_since = 0.0
        # always restore protection (idempotent)
        try:
            manager.set_ignore_protection(False)
        except Exception:
            pass

    # helper: safe flag getter
    def _flag_is_set(name):
        ev = globals().get(name)
        try:
            return bool(ev and ev.is_set())
        except Exception:
            return False
        
    def _adjacent_and_facing(ply_x, ply_y, npc_x, npc_y, live_dir):
        # desired facing from latest coords
        if   npc_x > ply_x: want = 3  # right/E
        elif npc_x < ply_x: want = 1  # left/W
        elif npc_y > ply_y: want = 0  # down/S
        elif npc_y < ply_y: want = 2  # up/N
        else:
            return False  # same tile / ambiguous
        dx = abs(ply_x - npc_x)
        dy = abs(ply_y - npc_y)
        dist = max(dx, dy)
        on_line = (ply_x == npc_x) or (ply_y == npc_y)
        return (live_dir == want) and on_line and (dist == 1)

    while True:
        # Check if bot should be running
        if not bot_running:
            _end_attack()
            time.sleep(0.1)
            continue
            
        # If a click sweep or home routine is running, DO NOT MOVE.
        if _flag_is_set('clicks_in_progress') or _flag_is_set('home_routine_running'):
            _end_attack()
            movement_start_time = None
            target_tile = None
            last_direction = None
            time.sleep(0.02)
            continue

        # Respect global movement pause (e.g., during loot/home)
        if not movement_allowed.is_set():
            _end_attack()
            time.sleep(0.05)
            continue

        now = time.time()

        # Expire temporary blocked tiles
        blocked_tiles = {tile: t for tile, t in blocked_tiles.items() if t > now}
        adjusted_walkable = base_walkable.difference(blocked_tiles.keys())

        # Need live map_data
        if not map_data:
            _end_attack()
            time.sleep(0.05)
            continue

        # Extract player
        try:
            player = next(item for item in map_data if item.get("type") == "player")
        except StopIteration:
            _end_attack()
            time.sleep(0.05)
            continue

        # Filter NPCs: type npc AND matches MOB_ID_FILTERS (if set)
        npcs = [n for n in map_data
                if n.get("type") == "npc" and (not MOB_ID_FILTERS or n.get("unique_id") in MOB_ID_FILTERS)]

        # --- Quarantine gate: for 2 minutes we do not attack; we only wander and avoid NPCs ---
        quarantined = (time.time() < speech_quarantine_until)

        if quarantined:
            # During quarantine we force wander: treat as if there are no valid NPCs
            valid_npcs = []
        else:
            # Normal path: only NPCs standing on walkable tiles
            valid_npcs = [npc for npc in npcs if (npc['X'], npc['Y']) in adjusted_walkable]

            filtered = []
            for npc in valid_npcs:
                addr = npc.get('address_x')
                if not addr:
                    continue
                if manager.is_protected(addr) and not (
                    addr == current_target_npc and (is_attacking() or recently_attacking(addr))
                ):
                    continue
                filtered.append(npc)
            valid_npcs = filtered

        if ctrl_pressed and not current_target_npc:
            _end_attack()

        # Reached previously set step tile?
        if target_tile and (player['X'], player['Y']) == target_tile:
            movement_start_time = None
            target_tile = None

        # If the current target is no longer present, treat as a kill and drop it immediately.
        if current_target_npc:
            present_addrs = {n.get("address_x") for n in npcs}
            if current_target_npc not in present_addrs:
                _end_attack()
                movement_start_time = None
                target_tile = None
                last_direction = None

                _fire_kill_once(current_target_npc, reason="VANISH")  # <- add
                current_target_npc = None                              # <- add

                time.sleep(0.05)
                continue

        # ---- No valid NPCs → wander ----
        if not valid_npcs:
            current_target_npc = None  # clear any stale choice

            _end_attack()

            # start / check the wander timer
            if _wander_since is None:
                _wander_since = time.monotonic()
            elif (time.monotonic() - _wander_since) >= WANDER_TIMEOUT_S:
                # time's up: re-run Home (only if that feature is on and not already running)
                if RUN_HOME_AFTER_KILL and not home_routine_running.is_set():
                    threading.Thread(target=_home_routine, daemon=True).start()
                    _wander_since = None
                    time.sleep(0.25)
                    continue  # skip doing a wander step this tick

            # Build an avoidance set during quarantine: NPC tiles + 4-neighbors
            if quarantined:
                danger = {(n['X'], n['Y']) for n in npcs}
                danger |= {(x+1, y) for (x, y) in danger}
                danger |= {(x-1, y) for (x, y) in danger}
                danger |= {(x, y+1) for (x, y) in danger}
                danger |= {(x, y-1) for (x, y) in danger}
                tiles_for_wander = adjusted_walkable.difference(danger) or adjusted_walkable
            else:
                tiles_for_wander = adjusted_walkable

            cur_pos = (player['X'], player['Y'])
            if last_position and cur_pos == last_position:
                if not stuck_timer_start:
                    stuck_timer_start = now
                elif now - stuck_timer_start > 0.5:
                    wandering_target = random.choice(list(tiles_for_wander))
                    stuck_timer_start = None
            else:
                stuck_timer_start = None
                last_position = cur_pos

            if not wandering_target or cur_pos == wandering_target:
                wandering_target = random.choice(list(tiles_for_wander))

            path_to_wander = astar_pathfinding(cur_pos, wandering_target, adjusted_walkable)
            if path_to_wander and len(path_to_wander) > 1:
                step_x, step_y = path_to_wander[1]

                move_dir = None
                if player['X'] < step_x:
                    move_dir = 'right'
                elif player['X'] > step_x:
                    move_dir = 'left'
                if player['Y'] < step_y:
                    move_dir = 'down'
                elif player['Y'] > step_y:
                    move_dir = 'up'

                if move_dir:
                    if move_dir != last_direction:
                        press_key(move_dir, 2, 0.05)
                    else:
                        press_key(move_dir, 1, 0.05)
                    last_direction = move_dir

            time.sleep(0.02)
            continue  # end wander tick

        # ---- We have NPCs and we're not sitting ----
        if not sitting:
            _wander_since = None
            npc_positions = {(n['X'], n['Y']) for n in valid_npcs}
            # Avoid stepping onto NPC tiles to keep LOS clearer
            extended_walkable = adjusted_walkable.difference(npc_positions)

            # Pick closest target
            closest = find_closest_npc(player['X'], player['Y'], valid_npcs)
            new_target = closest.get("address_x") if closest else None

            # --- Arm 5s immunity ONLY when target CHANGES (per-attach window; won't slide every tick) ---
            if new_target != current_target_npc:
                # clear retreat state on target swap
                if current_target_npc:
                    RANGE_MODE.pop(current_target_npc, None)
                if new_target:
                    _target_immunity_until[new_target] = time.monotonic() + IMMUNITY_SEC
                current_target_npc = new_target

            # If for some reason we have no target, skip the rest of this tick
            if not current_target_npc:
                _end_attack()
                time.sleep(0.02)
                continue

            target_obj = next((n for n in valid_npcs if n.get("address_x") == current_target_npc), None)
            if not target_obj:
                # target vanished between checks; let the vanish handler run next loop
                _end_attack()
                time.sleep(0.02)
                continue

            npc_x, npc_y = target_obj['X'], target_obj['Y']
            ply_x, ply_y = player['X'], player['Y']

            # ---- WATCHDOG: if CTRL is held but we're not actually aligned+adjacent, auto-release
            if ctrl_pressed:
                live_dir = int(player_data_manager.get_data().get('direction', 0))
                if not _adjacent_and_facing(ply_x, ply_y, npc_x, npc_y, live_dir):
                    if (time.time() - ctrl_pressed_since) > CTRL_MISALIGN_TIMEOUT:
                        print("[watchdog] misaligned while CTRL held -> release")
                        _end_attack()
                        # clear intent so next tick can re-close distance cleanly
                        movement_start_time = None
                        target_tile = None
                        wandering_target = None
                        current_target_npc = None
                        time.sleep(0.02)
                        continue

            # ------ STALE TARGET CHECK (remove stale NPCs, then reacquire) ------
            info = target_move_info.get(current_target_npc)
            pos_now = (npc_x, npc_y)

            if info is None:
                # first time tracking this target
                target_move_info[current_target_npc] = {"pos": pos_now, "ts": now}
            else:
                # update timestamp only when NPC moves
                if info["pos"] != pos_now:
                    info["pos"] = pos_now
                    info["ts"] = now

                # stale detection
                if (now - info["ts"]) >= LAST_MOVED_TIMER_SECONDS:
                    print(f"[STALE] Target {current_target_npc} unmoved for {LAST_MOVED_TIMER_SECONDS}s — removing")

                    # Stop attacking before removal
                    _end_attack()

                    # Try to remove the NPC from the address manager so it won't be reused
                    try:
                        if 'manager' in globals() and manager and current_target_npc:
                            manager.remove_address(current_target_npc)
                            print(f"[REMOVE] {current_target_npc} -> | reason: stale")
                    except Exception as e:
                        print(f"[WARN] failed to remove stale target {current_target_npc}: {e}")

                    # Mark stale removal for debugging
                    try:
                        import time as _t
                        globals().setdefault("RECENT_REMOVALS", {})[current_target_npc] = ("stale", _t.monotonic())
                    except Exception:
                        pass

                    # Clear any targeting/movement state
                    movement_start_time = None
                    target_tile = None
                    wandering_target = None
                    last_direction = None

                    # Drop current target
                    current_target_npc = None

                    # Immediately try to pick a new valid NPC
                    if valid_npcs:
                        # sort by distance, closest first
                        valid_npcs.sort(key=lambda n: abs(ply_x - n['X']) + abs(ply_y - n['Y']))
                        new_target = valid_npcs[0]
                        current_target_npc = new_target.get('addr') or new_target.get('address')
                        print(f"[TARGET] Switching to new target after stale: {current_target_npc}")
                    else:
                        # No NPCs nearby — start wander mode
                        _wander_since = time.monotonic()
                        wandering_target = None
                        print("[TARGET] No valid targets after stale removal, wandering...")

                    # short pause to let state settle
                    time.sleep(0.02)
                    continue

            dx = abs(ply_x - npc_x)
            dy = abs(ply_y - npc_y)


            # 4-second safety re-face (robust)
            if ctrl_pressed and (now - ctrl_pressed_since) >= 0.8:
                # decide the desired facing from player vs npc position
                target_dir_idx = None
                if npc_x > ply_x:   target_dir_idx = 3  # Right/East
                elif npc_x < ply_x: target_dir_idx = 1  # Left/West
                elif npc_y > ply_y: target_dir_idx = 0  # Down/South
                elif npc_y < ply_y: target_dir_idx = 2  # Up/North

                # live direction source (avoid stale snapshot)
                live_dir = player_data_manager.get_data().get('direction')

                if target_dir_idx is not None and live_dir != target_dir_idx:
                    print(f"[face] safety re-face: live {live_dir} → want {target_dir_idx}")

                    # release ctrl so the game will accept a turn
                    print("[face] releasing ctrl")
                    _end_attack()
                    time.sleep(0.03)  # debounce so release registers

                    desired = target_dir_idx
                    dir_key = ['down', 'left', 'up', 'right'][desired]

                    turned = False
                    for attempt in range(1, 3):
                        print(f"[face] tap {dir_key} (attempt {attempt}/2)")
                        press_key(dir_key, 1, 0.05)

                        t0 = time.time()
                        while time.time() - t0 < 0.30:
                            new_dir = player_data_manager.get_data().get('direction')
                            if new_dir == desired:
                                print(f"[face] turned OK → {new_dir}")
                                turned = True
                                break
                            time.sleep(0.02)
                        if turned:
                            break

                    # Recompute live facing/desired, then only re-hold if we're actually aligned AND adjacent.
                    live_dir = player_data_manager.get_data().get('direction')

                    live = int(player_data_manager.get_data().get('direction', 0))
                    # make sure we read latest coords (target_obj may have moved)
                    ply_x, ply_y = player['X'], player['Y']
                    npc_x, npc_y = target_obj['X'], target_obj['Y']

                    if _adjacent_and_facing(ply_x, ply_y, npc_x, npc_y, live):
                        _begin_attack(current_target_npc)

                        # --- POST-HOLD VERIFY (stage 2): bail out fast if target jukes after hold ---
                        t0 = time.time()
                        ok = False
                        while time.time() - t0 < 0.16:           # ~100–160ms sanity window
                            d = int(player_data_manager.get_data().get('direction', live))
                            # refresh positions; the target may slide during our hold
                            ply_x, ply_y = player['X'], player['Y']
                            npc_x, npc_y = target_obj['X'], target_obj['Y']
                            if _adjacent_and_facing(ply_x, ply_y, npc_x, npc_y, d):
                                ok = True
                                break
                            time.sleep(0.02)

                        if not ok:
                            print("[face] post-hold failed (target moved) → release + retarget")
                            _end_attack()

                            # clear intent/target so movement can re-close distance
                            movement_start_time = None
                            target_tile = None
                            wandering_target = None
                            current_target_npc = None
                            time.sleep(0.02)
                            continue
                    else:
                        print("[face] not aligned/adjacent → NO hold; retarget")
                        _end_attack()
                        movement_start_time = None
                        target_tile = None
                        wandering_target = None
                        current_target_npc = None
                        time.sleep(0.02)
                        continue

            # Helper (put this near your other helpers):
            def get_flank_candidates(npc_x, npc_y, r):
                # four tiles exactly r away on same row/col
                return [
                    (npc_x - r, npc_y), (npc_x + r, npc_y),
                    (npc_x, npc_y - r), (npc_x, npc_y + r),
                ]

            ENGAGE_RANGE    = FLANK_RANGE   # usually 3; reads your current setting each tick
            RETREAT_TRIGGER = 0 if ENGAGE_RANGE == 1 else 1

            # Helper: LOS using Bresenham against adjusted_walkable
            def has_los(ax, ay, bx, by):
                los = list(bresenham.bresenham(ax, ay, bx, by))
                return all((x, y) in adjusted_walkable for x, y in los)

            # Distance metrics
            on_line = (ply_y == npc_y) or (ply_x == npc_x)
            dist    = max(dx, dy)

            # ★ read/normalize sticky retreat state
            state = RANGE_MODE.get(current_target_npc)
            if state == "retreating" and dist >= ENGAGE_RANGE:
                RANGE_MODE.pop(current_target_npc, None)
                state = None

            # ---------- 1) RETREAT band (≤ 1 OR still retreating until 3) ----------
            if on_line and has_los(ply_x, ply_y, npc_x, npc_y) and (
                dist <= RETREAT_TRIGGER or (state == "retreating" and dist < ENGAGE_RANGE)
            ):
                RANGE_MODE[current_target_npc] = "retreating"  # ★ stick

                # release attack so we can move
                _end_attack()

                # target a flank tile at ENGAGE_RANGE, ideally on the opposite side
                def get_flank_candidates(npc_x, npc_y, r):
                    return [
                        (npc_x - r, npc_y), (npc_x + r, npc_y),
                        (npc_x, npc_y - r), (npc_x, npc_y + r),
                    ]

                flank_candidates = get_flank_candidates(npc_x, npc_y, ENGAGE_RANGE)

                # Favor candidates that are farther from the NPC (ensures we truly back out)
                flank_candidates.sort(key=lambda p: -max(abs(p[0] - npc_x), abs(p[1] - npc_y)))

                # Only step onto non-NPC tiles we consider walkable
                flank_valid = [pos for pos in flank_candidates if pos in extended_walkable]

                def try_paths(cands):
                    paths = []
                    for tgt in cands:
                        p = astar_pathfinding((ply_x, ply_y), tgt, adjusted_walkable)
                        if p:
                            paths.append((p, tgt))
                    return min(paths, key=lambda x: len(x[0])) if paths else None

                best = try_paths(flank_valid) or try_paths([p for p in flank_candidates if p in adjusted_walkable])

                if best:
                    path, _ = best
                    # step one tile along the path
                    if len(path) > 1:
                        step_x, step_y = path[1]

                        if (step_x, step_y) != target_tile:
                            movement_start_time = now
                            target_tile = (step_x, step_y)

                        move_dir = None
                        if ply_x < step_x:   move_dir = 'right'
                        elif ply_x > step_x: move_dir = 'left'
                        if ply_y < step_y:   move_dir = 'down'
                        elif ply_y > step_y: move_dir = 'up'

                        if move_dir:
                            if move_dir != last_direction:
                                press_key(move_dir, 2, 0.05)
                            else:
                                press_key(move_dir, 1, 0.05)
                            last_direction = move_dir

                        # If we've been trying for >2s and didn't reach that tile, mark it blocked briefly
                        if movement_start_time and (now - movement_start_time) > 2.0:
                            if (player['X'], player['Y']) != (step_x, step_y):
                                blocked_tiles[(step_x, step_y)] = now + 3.0
                            movement_start_time = None

                time.sleep(0.02)
                continue

            # ---------- 2) HOLD/ATTACK band (2 or 3): never step back up to 3 if at 2 ----------
            if (RANGE_MODE.get(current_target_npc) != "retreating"
                and on_line
                and 1 <= dist <= ENGAGE_RANGE
                and has_los(ply_x, ply_y, npc_x, npc_y)):
                # face target (0:S,1:W,2:N,3:E)
                target_dir_idx = None
                if npc_x > ply_x:   target_dir_idx = 3  # East
                elif npc_x < ply_x: target_dir_idx = 1  # West
                elif npc_y > ply_y: target_dir_idx = 0  # South
                elif npc_y < ply_y: target_dir_idx = 2  # North

                player_dir = player.get('direction')
                if target_dir_idx is not None and player_dir != target_dir_idx:
                    time.sleep(0.2)
                    press_key(['down', 'left', 'up', 'right'][target_dir_idx], 1, 0.05)

                if not ctrl_pressed:
                    _begin_attack(current_target_npc)

                last_combat_time = now
                time.sleep(0.02)
                continue

            # ---------- 3) APPROACH band (> 3): walk to a flank tile at 3 ----------
            if dist > ENGAGE_RANGE:
                _end_attack()

                def get_flank_candidates(npc_x, npc_y, r):
                    return [
                        (npc_x - r, npc_y), (npc_x + r, npc_y),
                        (npc_x, npc_y - r), (npc_x, npc_y + r),
                    ]

                flank_candidates = get_flank_candidates(npc_x, npc_y, ENGAGE_RANGE)
                flank_valid = [pos for pos in flank_candidates if pos in extended_walkable]

                def try_paths(candidates):
                    paths = []
                    for tgt in candidates:
                        p = astar_pathfinding((ply_x, ply_y), tgt, adjusted_walkable)
                        if p:
                            paths.append((p, tgt))
                    return min(paths, key=lambda x: len(x[0])) if paths else None

                best = try_paths(flank_valid) or try_paths([p for p in flank_candidates if p in adjusted_walkable])

                if best:
                    best_path, _ = best
                    if len(best_path) > 1:
                        if not best or not best[0] or len(best[0]) < 2:
                            movement_start_time = None
                            time.sleep(0.02); continue
                        step_x, step_y = best[0][1]
                        step_x, step_y = best_path[1]

                        if (step_x, step_y) != target_tile:
                            movement_start_time = now
                            target_tile = (step_x, step_y)

                        move_dir = None
                        if ply_x < step_x:   move_dir = 'right'
                        elif ply_x > step_x: move_dir = 'left'
                        if ply_y < step_y:   move_dir = 'down'
                        elif ply_y > step_y: move_dir = 'up'

                        if move_dir:
                            if move_dir != last_direction:
                                press_key(move_dir, 2, 0.05)
                            else:
                                press_key(move_dir, 1, 0.05)
                            last_direction = move_dir

                        # timeout → temporarily block sticky tiles
                        if movement_start_time and (now - movement_start_time) > 2.0:
                            if (player['X'], player['Y']) != (step_x, step_y):
                                blocked_tiles[(step_x, step_y)] = now + 3.0
                            movement_start_time = None

                time.sleep(0.02)
                continue

            # ---- default flank walk (fallback) ----
            flank_candidates = get_flank_candidates(npc_x, npc_y, FLANK_RANGE)
            flank_valid = [pos for pos in flank_candidates if pos in extended_walkable]

            def try_paths(candidates):
                paths = []
                for tgt in candidates:
                    p = astar_pathfinding((ply_x, ply_y), tgt, adjusted_walkable)
                    if p:
                        paths.append((p, tgt))
                if not paths:
                    return None
                return min(paths, key=lambda x: len(x[0]))

            best = try_paths(flank_valid) or try_paths([p for p in flank_candidates if p in adjusted_walkable])

            if best:
                best_path, _ = best
                if not best or not best[0] or len(best[0]) < 2:
                    movement_start_time = None
                    time.sleep(0.02); continue
                step_x, step_y = best[0][1]
                step_x, step_y = best_path[1]

                if (step_x, step_y) != target_tile:
                    movement_start_time = now
                    target_tile = (step_x, step_y)

                move_dir = None
                if ply_x < step_x:
                    move_dir = 'right'
                elif ply_x > step_x:
                    move_dir = 'left'
                if ply_y < step_y:
                    move_dir = 'down'
                elif ply_y > step_y:
                    move_dir = 'up'

                if move_dir:
                    if move_dir != last_direction:
                        press_key(move_dir, 2, 0.05)
                    else:
                        press_key(move_dir, 1, 0.05)
                    last_direction = move_dir

                # If we tried to move for >2s and didn't reach that tile, mark it blocked for 3s
                if movement_start_time and (now - movement_start_time) > 2.0:
                    if (player['X'], player['Y']) != (step_x, step_y):
                        blocked_tiles[(step_x, step_y)] = now + 3.0
                    movement_start_time = None

                time.sleep(0.02)
                continue

        # Safety: if we fall through this tick, release attack and restore protection
        _end_attack()

        time.sleep(0.02)


def main():
    global bot_running, totalExp, combat_baseline_exp, resurrect_points
    load_settings()
    bot_running = False
    combat_baseline_exp = 0
    # Only prompt for click locations if they weren't loaded from config
    if not resurrect_points or len(resurrect_points) != 4:
        record_direction_points()
    else:
        print(f"[SETUP] Using saved click locations: {resurrect_points}")
    walk_address = walkAddress
    npc_address = npcAddress
    directional_offset = directionalAddress

    print("Using hardcoded offsets:")
    print(f"Walk Address: {walk_address}")
    print(f"NPC Address: {npc_address}")
    print(f"Directional Address: {directional_offset}")

    # Patch & mem
    patch_adds_with_nops()
    initialize_pymem()

    # Hooks: keep EXP hook for stats GUI; kill logic does NOT rely on EXP
    start_frida_exp()
    start_frida_session_xy(walkAddress)
    start_frida_session_directional(directionalAddress)
    threading.Thread(target=start_frida, args=(npc_address,), daemon=True).start()
    threading.Thread(target=start_frida_weight_lock, args=(WEIGHT_WRITE_ADDRS,), daemon=True).start()

    # Monitors/loops
    threading.Thread(target=check_player_data, args=(x_address, y_address, directional_address), daemon=True).start()
    threading.Thread(target=combat_thread, daemon=True).start()
    threading.Thread(target=key_listener, daemon=True).start()
    threading.Thread(target=_quarantine_cleanup_loop, daemon=True).start()
    threading.Thread(target=start_frida_speech_monitor, daemon=True).start()

    # GUI (blocks)
    PlayerDataPopup(player_data_manager).run()

if __name__ == "__main__":
    main()