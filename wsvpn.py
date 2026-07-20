import os
import sys
import re
import time
import socket
import string
import random
import threading
import traceback
import base64
import urllib.parse
import io
import json
import sqlite3
from Crypto.Util.Padding import unpad
import warnings
import urllib3
from datetime import datetime, timedelta
from threading import Thread, Lock, Event
from waitress import serve
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from functools import wraps
from collections import defaultdict
import uuid

import telebot
from telebot import types
import requests
from bs4 import BeautifulSoup
from flask import Flask, request

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SECRET_WORD_STR = os.getenv("SECRET_WORD", "7zR$8qM!2p@K9x#V")
SECRET_WORD = SECRET_WORD_STR.encode('utf-8')[:16].ljust(16, b'\0')

# Чтение пароля для веб-административной панели из Render
WEB_PASSWORD = os.getenv("WEB_PASSWORD", "")

# ==================== КОНСТАНТЫ ====================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

try:
    import psycopg2
    PSY_AVAILABLE = True
except ImportError:
    PSY_AVAILABLE = False

_cache_lock = Lock()
_subscribe_monitor_lock = Lock()
_captcha_lock = Lock()
_keys_lock = Lock()
_user_name_cache_lock = Lock()
_last_activity_lock = Lock()
_rate_limit_lock = Lock()
_maintenance_mode_cache = False
_maintenance_lock = Lock()


MENU_BUTTONS = {
    "👤 Личный кабинет", "📡 Моя подписка",
    "👥 Рефералы", "🏆 Топ рефералов",
    "ℹ️ Стаж бота", "📋 Правила",
    "❓ Поддержка"
}

def load_maintenance_mode():
    """Загружает состояние режима тех. работ из БД в RAM при старте бота"""
    global _maintenance_mode_cache
    val = get_setting("maintenance_mode", "0")
    with _maintenance_lock:
        _maintenance_mode_cache = (val == "1")
        print(f"[init] 🛠 Режим тех. обслуживания загружен из БД: {_maintenance_mode_cache}")

def set_maintenance_mode(state_str):
    """Сохраняет состояние режима тех. работ и в БД, и в RAM"""
    global _maintenance_mode_cache
    set_setting("maintenance_mode", state_str)
    with _maintenance_lock:
        _maintenance_mode_cache = (state_str == "1")

def is_maintenance_active():
    """Безопасно и мгновенно возвращает статус тех. работ из оперативной памяти"""
    with _maintenance_lock:
        return _maintenance_mode_cache

# ==========================================
# БЛОК ШИФРОВАНИЯ (AES-128-ECB) СПЕЦ. СЛОВОМ
# ==========================================

def parse_and_encrypt_vless(vless_url, expire_timestamp=None):
    """Шифрует сырую ссылку напрямую с помощью AES-128-ECB и SECRET_WORD"""
    if not vless_url:
        return None
        
    vless_url = vless_url.strip()
    if not vless_url.startswith(("vless://", "vmess://", "trojan://", "ss://")):
        return vless_url # Возвращаем как есть, если это не поддерживаемый протокол
        
    try:
        cipher = AES.new(SECRET_WORD, AES.MODE_ECB)
        padded_data = pad(vless_url.encode('utf-8'), 16)
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"[encrypt] Ошибка шифрования ссылки: {e}")
        return None

def decrypt_and_parse_vless(encrypted_b64):
    """Дешифрует одиночную строку обратно в сырую ссылку"""
    if not encrypted_b64:
        return None
    try:
        encrypted_b64 = encrypted_b64.strip()
        encrypted_data = base64.b64decode(encrypted_b64)
        cipher = AES.new(SECRET_WORD, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted_data)
        return unpad(decrypted, 16).decode('utf-8')
    except Exception as e:
        # Тихо игнорируем ошибку, если строка не зашифрована
        return None

def decrypt_any_subscription_input(raw_input):
    """Дешифрует как одиночную строку, так и полный Base64-бандл"""
    raw_input = raw_input.strip()
    if not raw_input:
        return []
    
    # 1. Пробуем как одиночную строку
    decrypted = decrypt_and_parse_vless(raw_input)
    if decrypted and decrypted.startswith(("vless://", "vmess://", "trojan://", "ss://")):
        return [decrypted]
        
    # 2. Пробуем как бандл
    try:
        outer_decoded = base64.b64decode(raw_input).decode('utf-8')
        lines = [line.strip() for line in outer_decoded.split('\n') if line.strip()]
        results = []
        for line in lines:
            dec = decrypt_and_parse_vless(line)
            if dec and dec.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                results.append(dec)
        return results
    except Exception as e:
        print(f"[decrypt_any] Не удалось распознать: {e}")
        
    return []

def parse_and_encrypt_vless(vless_url, expire_timestamp=None):
    """Шифрует сырую ссылку напрямую БЕЗ даты окончания подписки"""
    if not vless_url or not vless_url.startswith(("vless://", "vmess://", "trojan://", "ss://")):
        return None
    try:
        cipher = AES.new(SECRET_WORD, AES.MODE_ECB)
        padded_data = pad(vless_url.encode('utf-8'), 16)
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"[encrypt] Ошибка шифрования ссылки: {e}")
        return None

def keep_alive_ping():
    url = os.getenv('RENDER_EXTERNAL_URL', '')
    if not url:
        url = os.getenv('PUBLIC_URL', '')
    if not url:
        url = 'http://localhost:8080/'
    url = url.rstrip('/')
    print(f"[keep_alive] Запущен пинг-механизм для {url}")
    ping_count = 0
    while True:
        try:
            response = requests.get(f"{url}/ping", timeout=10)
            ping_count += 1
            if ping_count > 1000000:
                ping_count = 0
            print(f"[keep_alive] Пинг #{ping_count} в {datetime.now().strftime('%H:%M:%S')}: {response.status_code}")
            requests.get(f"{url}/health", timeout=10)
        except SystemExit:
            break
        except Exception as e:
            print(f"[keep_alive] Ошибка пинга: {e}")
        time.sleep(240)

def auto_restart_monitor():
    max_idle_time = 600
    print(f"[auto_restart] Запущен монитор перезапуска")
    while True:
        try:
            current_time = time.time()
            with _last_activity_lock:
                idle_time = current_time - last_activity_time
            if idle_time > max_idle_time:
                print(f"[auto_restart] Длительное бездействие, выполняем мягкий перезапуск...")
                try:
                    url = os.getenv('RENDER_EXTERNAL_URL', 'https://wsvpn-bobot.onrender.com')
                    for _ in range(3):
                        requests.get(f"{url}/ping", timeout=5)
                        time.sleep(1)
                except:
                    pass
            time.sleep(30)
        except:
            time.sleep(60)

last_activity_time = time.time()

def update_activity():
    global last_activity_time
    with _last_activity_lock:
        last_activity_time = time.time()

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    print("❌ КРИТИЧЕСКАЯ ОШИБКА: Переменная окружения BOT_TOKEN не задана в панели Render!")
    sys.exit(1)
ADMIN_ID = int(os.getenv("ADMIN_ID"))
CHANNEL_ID = -1003848589461
CHANNEL_LINK = 'https://t.me/WS_JuJuB01_vpn_keys'
SUPPORT = '@WS_JuJuB01'

bot = telebot.TeleBot(BOT_TOKEN, threaded=True, num_threads=8)
app = Flask(__name__)

# ==================== БЕЗОПАСНАЯ ОТПРАВКА СООБЩЕНИЙ ====================

def escape_markdown(text):
    if text is None:
        return ""
    text = str(text)
    for ch in ('_', '*', '`', '['):
        text = text.replace(ch, '\\' + ch)
    return text


def _is_parse_entities_error(exc):
    return "can't parse entities" in str(exc).lower()


_original_send_message = bot.send_message
_original_reply_to = bot.reply_to
_original_edit_message_text = bot.edit_message_text


def _safe_send_message(chat_id, text, *args, **kwargs):
    try:
        return _original_send_message(chat_id, text, *args, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if kwargs.get('parse_mode') and _is_parse_entities_error(e):
            print(f"[safe_send_message] Ошибка разметки, повтор без parse_mode: {e}")
            kwargs['parse_mode'] = None
            return _original_send_message(chat_id, text, *args, **kwargs)
        raise


def _safe_reply_to(message, text, *args, **kwargs):
    try:
        return _original_reply_to(message, text, *args, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if kwargs.get('parse_mode') and _is_parse_entities_error(e):
            print(f"[safe_reply_to] Ошибка разметки, повтор без parse_mode: {e}")
            kwargs['parse_mode'] = None
            return _original_reply_to(message, text, *args, **kwargs)
        raise


def _safe_edit_message_text(text, *args, **kwargs):
    try:
        return _original_edit_message_text(text, *args, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if kwargs.get('parse_mode') and _is_parse_entities_error(e):
            print(f"[safe_edit_message_text] Ошибка разметки, повтор без parse_mode: {e}")
            kwargs['parse_mode'] = None
            return _original_edit_message_text(text, *args, **kwargs)
        raise


bot.send_message = _safe_send_message
bot.reply_to = _safe_reply_to
bot.edit_message_text = _safe_edit_message_text

def get_bot_base_url():
    base_url = os.getenv('RENDER_EXTERNAL_URL', '')
    if not base_url:
        base_url = os.getenv('PUBLIC_URL', 'https://wsvpn-bobot.onrender.com')
    base_url = base_url.rstrip('/')
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    return base_url

db_pool = None

def init_db_pool():
    print("[db] ✅ Система SQLite готова")
    return None

class SQLiteWrapper:
    """Умная обертка для автоматической конвертации запросов Postgres -> SQLite"""
    def __init__(self, conn):
        self.conn = conn
    def cursor(self):
        return CursorWrapper(self.conn.cursor())
    def commit(self):
        return self.conn.commit()
    def rollback(self):
        return self.conn.rollback()
    def close(self):
        return self.conn.close()

class CursorWrapper:
    def __init__(self, cursor):
        self.cursor = cursor
    def execute(self, query, params=None):
        fixed_query = query.replace('%s', '?').replace('FOR UPDATE', '').replace('SERIAL PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
        if params:
            return self.cursor.execute(fixed_query, params)
        return self.cursor.execute(fixed_query)
    def fetchone(self):
        return self.cursor.fetchone()
    def fetchall(self):
        return self.cursor.fetchall()
    def close(self):
        return self.cursor.close()
    def __iter__(self):
        return iter(self.cursor)
    @property
    def lastrowid(self):
        return self.cursor.lastrowid

def get_db_connection():
    # Загружаем адрес подключения к PostgreSQL из панели управления Render
    database_url = os.getenv("DATABASE_URL", "")
    
    if database_url and PSY_AVAILABLE:
        try:
            conn = psycopg2.connect(database_url)
            return conn
        except Exception as e:
            print(f"[db] Предупреждение: не удалось подключиться к PostgreSQL ({e}). Переход на SQLite...")
            
    conn = sqlite3.connect("wsvpn.db", check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return SQLiteWrapper(conn)

def return_db_connection(db_conn):
    if db_conn:
        try:
            db_conn.commit()
        except:
            pass
        try:
            # Безопасно закрываем обертку SQLiteWrapper или стандартное соединение PostgreSQL
            if hasattr(db_conn, 'conn'):
                db_conn.conn.close()
            else:
                db_conn.close()
        except:
            pass
        
search_cache = {}
announce_data = {}
manage_cache = {}
captcha_sessions = {}
keys_loading = {}

_user_name_cache = {}
USER_NAME_CACHE_TTL = 3600

_keys_cache = None
_keys_cache_time = 0
KEYS_CACHE_TTL = 60

_bot_username = None
_bot_username_lock = Lock()

_user_blocked_cache = {}
_user_blocked_cache_lock = Lock()
USER_BLOCKED_CACHE_TTL = 3600

def safe_get_cache(cache_dict, key, default=None):
    with _cache_lock:
        return cache_dict.get(key, default)

def safe_set_cache(cache_dict, key, value):
    with _cache_lock:
        cache_dict[key] = value

def safe_del_cache(cache_dict, key):
    with _cache_lock:
        if key in cache_dict:
            del cache_dict[key]

def safe_cache_keys(cache_dict):
    with _cache_lock:
        return list(cache_dict.keys())

SESSION_TIMEOUT = 3600

def cleanup_expired_sessions():
    current_time = int(time.time())
    
    with _cache_lock:
        to_remove = [uid for uid, session in captcha_sessions.items() 
                     if current_time - session.get('timestamp', 0) > SESSION_TIMEOUT]
        for uid in to_remove:
            del captcha_sessions[uid]
        
        to_remove = [uid for uid, cache in search_cache.items() 
                     if current_time - cache.get('timestamp', 0) > SESSION_TIMEOUT]
        for uid in to_remove:
            del search_cache[uid]
        
        to_remove = [uid for uid, data in announce_data.items() 
                     if current_time - data.get('timestamp', 0) > SESSION_TIMEOUT]
        for uid in to_remove:
            del announce_data[uid]
        
        to_remove = [uid for uid, data in keys_loading.items() 
                     if current_time - data.get('timestamp', 0) > SESSION_TIMEOUT]
        for uid in to_remove:
            del keys_loading[uid]
        
        to_remove = [uid for uid, data in manage_cache.items() 
                     if current_time - data.get('timestamp', 0) > SESSION_TIMEOUT]
        for uid in to_remove:
            del manage_cache[uid]
    
    with _user_name_cache_lock:
        to_remove = [
            uid for uid, data in _user_name_cache.items()
            if current_time - data.get('timestamp', 0) > USER_NAME_CACHE_TTL
        ]
        for uid in to_remove:
            del _user_name_cache[uid]
    
    with _user_blocked_cache_lock:
        to_remove = [
            uid for uid, data in _user_blocked_cache.items()
            if current_time - data.get('timestamp', 0) > USER_BLOCKED_CACHE_TTL * 2
        ]
        for uid in to_remove:
            del _user_blocked_cache[uid]

def cleanup_sessions_scheduler():
    print("[cleanup] Запущен планировщик очистки сессий")
    last_notify = 0
    last_expired_notify = 0
    while True:
        try:
            cleanup_expired_sessions()
            current_time = int(time.time())
            
            if current_time - last_notify >= 3600:
                _notify_expiring_subscriptions()
                last_notify = current_time
            if current_time - last_expired_notify >= 6 * 3600:
                _notify_expired_subscriptions()
                last_expired_notify = current_time
            time.sleep(300)
        except Exception as e:
            print(f"[cleanup] Ошибка: {e}")
            time.sleep(60)

def _notify_expiring_subscriptions():
    current_time = int(time.time())
    threshold = current_time + 3 * 24 * 60 * 60
    conn = get_db_connection()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT user_id, subscription_end FROM users
            WHERE is_blocked = 0
              AND notified_3days = 0
              AND subscription_end > %s
              AND subscription_end <= %s
        """, (current_time, threshold))
        rows = cur.fetchall()
        for user_id, sub_end in rows:
            days_left = (sub_end - current_time) // (24 * 60 * 60)
            try:
                bot.send_message(
                    user_id,
                    f"⚠️ *Подписка заканчивается через {days_left} дн.*\n\n"
                    f"Для продления обратитесь в поддержку: {SUPPORT}",
                    parse_mode="Markdown"
                )
                cur.execute(
                    "UPDATE users SET notified_3days = 1 WHERE user_id = %s",
                    (user_id,)
                )
                conn.commit()
            except Exception as e:
                print(f"[notify] Ошибка отправки {user_id}: {e}")
                continue
    except Exception as e:
        print(f"[notify] Ошибка: {e}")
        try:
            conn.rollback()
        except:
            pass
    finally:
        if cur:
            try:
                cur.close()
            except:
                pass
        return_db_connection(conn)

def _notify_expired_subscriptions():
    current_time = int(time.time())
    conn = get_db_connection()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT user_id FROM users
            WHERE is_blocked = 0
              AND is_frozen = 0
              AND notified_expired = 0
              AND subscription_end > 0
              AND subscription_end < %s
        """, (current_time,))
        rows = cur.fetchall()
        for (user_id,) in rows:
            try:
                bot.send_message(
                    user_id,
                    f"❌ *Ваша подписка истекла*\n\n"
                    f"Для продления обратитесь в поддержку: {SUPPORT}",
                    parse_mode="Markdown"
                )
                cur.execute(
                    "UPDATE users SET notified_expired = 1 WHERE user_id = %s",
                    (user_id,)
                )
                conn.commit()
            except Exception as e:
                print(f"[notify_expired] Ошибка отправки {user_id}: {e}")
                continue
    except Exception as e:
        print(f"[notify_expired] Ошибка: {e}")
        try:
            conn.rollback()
        except:
            pass
    finally:
        if cur:
            try:
                cur.close()
            except:
                pass
        return_db_connection(conn)

KEY_TEMPLATE = """\
#profile-title: WSVPN🐈‍⬛
#profile-update-interval: 1
#support-url: https://t.me/WS_JuJuB01
#announce: 📡 Полностью бесплатный | без скрытых условий/подписок | без логов
#channel: 📢 https://t.me/WS_JuJuB01_vpn_keys
#subscription-userinfo: upload=0; download=0; total=10995116277760000; expire={expire}
{keys}"""

def get_keys_from_db():
    global _keys_cache, _keys_cache_time
    current_time = time.time()
    
    with _keys_lock:
        if _keys_cache is not None and current_time - _keys_cache_time < KEYS_CACHE_TTL:
            return _keys_cache.copy()
        
        val = get_setting('vless_keys', '')
        if not val:
            keys = []
        else:
            keys = [k for k in val.split('|||') if k]
        
        _keys_cache = keys.copy()
        _keys_cache_time = current_time
        return keys

def save_keys_to_db(keys):
    global _keys_cache, _keys_cache_time
    cleaned = []
    seen = set()
    for k in keys:
        if k and k not in seen:
            cleaned.append(k)
            seen.add(k)
    
    with _keys_lock:
        set_setting('vless_keys', '|||'.join(cleaned))
        _keys_cache = cleaned.copy()
        _keys_cache_time = time.time()

def get_subscription_keys_from_db():
    """Получает упорядоченный список конфигураций из базы данных"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Достаем ключи строго в порядке их добавления (по ID)
        cur.execute("SELECT key_value FROM subscription_keys ORDER BY id ASC")
        return [row[0] for row in cur.fetchall()]
    except Exception as e:
        print(f"[db] Ошибка при чтении ключей подписки: {e}")
        return []
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

def save_subscription_keys_to_db(keys):
    """Дедуплицирует ключи с сохранением порядка и записывает их в БД"""
    cleaned = list(dict.fromkeys(k for k in keys if k))
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Очищаем таблицу перед перезаписью
        cur.execute("DELETE FROM subscription_keys")
        
        # Построчно вставляем новые ключи подписки
        current_time = int(time.time())
        for k in cleaned:
            cur.execute("""
                INSERT INTO subscription_keys (key_value, created_at) 
                VALUES (%s, %s)
                ON CONFLICT (key_value) DO NOTHING
            """, (k, current_time))
        conn.commit()
    except Exception as e:
        print(f"[db] Ошибка при сохранении ключей подписки: {e}")
        try:
            conn.rollback()
        except:
            pass
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

def _build_vless_link(outbound, remark=None):
    settings = outbound.get('settings', {}) or {}
    stream = outbound.get('streamSettings', {}) or {}
    vnext_list = settings.get('vnext', [])
    if not vnext_list:
        return None
    vnext = vnext_list[0]
    address, port = vnext.get('address'), vnext.get('port')
    users = vnext.get('users', [])
    if not (users and address and port):
        return None
    user = users[0]
    uid = user.get('id')
    if not uid:
        return None

    network = stream.get('network', 'tcp')
    security = stream.get('security', 'none')
    params = {'encryption': user.get('encryption', 'none'), 'security': security, 'type': network}
    if user.get('flow'):
        params['flow'] = user['flow']

    if network == 'ws':
        ws = stream.get('wsSettings', {}) or {}
        if ws.get('path'):
            params['path'] = ws['path']
        if (ws.get('headers') or {}).get('Host'):
            params['host'] = ws['headers']['Host']
    elif network == 'grpc':
        grpc = stream.get('grpcSettings', {}) or {}
        if grpc.get('serviceName'):
            params['serviceName'] = grpc['serviceName']

    if security == 'tls':
        tls = stream.get('tlsSettings', {}) or {}
        if tls.get('serverName'):
            params['sni'] = tls['serverName']
        if tls.get('fingerprint'):
            params['fp'] = tls['fingerprint']
    elif security == 'reality':
        rl = stream.get('realitySettings', {}) or {}
        if rl.get('serverName'):
            params['sni'] = rl['serverName']
        if rl.get('fingerprint'):
            params['fp'] = rl['fingerprint']
        if rl.get('publicKey'):
            params['pbk'] = rl['publicKey']
        if rl.get('shortId'):
            params['sid'] = rl['shortId']

    query = urllib.parse.urlencode(params)
    name = urllib.parse.quote(remark or outbound.get('tag') or 'key')
    return f"vless://{uid}@{address}:{port}?{query}#{name}"


def _build_vmess_link(outbound, remark=None):
    settings = outbound.get('settings', {}) or {}
    stream = outbound.get('streamSettings', {}) or {}
    vnext_list = settings.get('vnext', [])
    if not vnext_list:
        return None
    vnext = vnext_list[0]
    address, port = vnext.get('address'), vnext.get('port')
    users = vnext.get('users', [])
    if not (users and address and port):
        return None
    user = users[0]
    uid = user.get('id')
    if not uid:
        return None

    network = stream.get('network', 'tcp')
    security = stream.get('security', 'none')
    obj = {
        'v': '2', 'ps': remark or outbound.get('tag', 'key'),
        'add': address, 'port': str(port), 'id': uid,
        'aid': str(user.get('alterId', 0)), 'net': network,
        'type': 'none', 'tls': 'tls' if security == 'tls' else ''
    }
    if network == 'ws':
        ws = stream.get('wsSettings', {}) or {}
        obj['path'] = ws.get('path', '')
        obj['host'] = (ws.get('headers') or {}).get('Host', '')
    if security == 'tls':
        obj['sni'] = (stream.get('tlsSettings', {}) or {}).get('serverName', '')

    return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


def _build_trojan_link(outbound, remark=None):
    settings = outbound.get('settings', {}) or {}
    stream = outbound.get('streamSettings', {}) or {}
    servers = settings.get('servers', [])
    if not servers:
        return None
    s = servers[0]
    address, port, password = s.get('address'), s.get('port'), s.get('password')
    if not (address and port and password):
        return None
    network = stream.get('network', 'tcp')
    security = stream.get('security', 'tls')
    params = {'type': network, 'security': security}
    if security == 'tls':
        tls = stream.get('tlsSettings', {}) or {}
        if tls.get('serverName'):
            params['sni'] = tls['serverName']
    query = urllib.parse.urlencode(params)
    name = urllib.parse.quote(remark or outbound.get('tag') or 'key')
    return f"trojan://{password}@{address}:{port}?{query}#{name}"


def _build_ss_link(outbound, remark=None):
    servers = (outbound.get('settings', {}) or {}).get('servers', [])
    if not servers:
        return None
    s = servers[0]
    address, port = s.get('address'), s.get('port')
    method, password = s.get('method'), s.get('password')
    if not (address and port and method and password):
        return None
    userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
    name = urllib.parse.quote(remark or outbound.get('tag') or 'key')
    return f"ss://{userinfo}@{address}:{port}#{name}"


_PROTOCOL_BUILDERS = {
    'vless': _build_vless_link, 'vmess': _build_vmess_link,
    'trojan': _build_trojan_link, 'shadowsocks': _build_ss_link,
}


def extract_links_from_json(data):
    """Достаёт ключи из JSON: массив ссылок, {"keys"/"links": [...]},
    полный v2ray/xray конфиг с outbounds, список или один outbound."""
    links = []

    def handle_outbound(ob):
        if not isinstance(ob, dict):
            return
        builder = _PROTOCOL_BUILDERS.get((ob.get('protocol') or '').lower())
        if not builder:
            return
        try:
            link = builder(ob, ob.get('tag'))
            if link:
                links.append(link)
        except Exception as e:
            print(f"[extract_links_from_json] Ошибка конвертации: {e}")

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str) and '://' in item:
                links.append(item.strip())
            elif isinstance(item, dict):
                if 'protocol' in item:
                    handle_outbound(item)
                elif isinstance(item.get('outbounds'), list):
                    for ob in item['outbounds']:
                        handle_outbound(ob)
    elif isinstance(data, dict):
        for field in ('keys', 'links', 'subscription', 'urls'):
            if isinstance(data.get(field), list):
                for item in data[field]:
                    if isinstance(item, str) and '://' in item:
                        links.append(item.strip())
        if isinstance(data.get('outbounds'), list):
            for ob in data['outbounds']:
                handle_outbound(ob)
        elif 'protocol' in data:
            handle_outbound(data)

    return links

def generate_subscription_token():
    import secrets
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(16))

def ensure_bot_start_time():
    existing = get_setting('bot_start_time', '')
    if not existing:
        set_setting('bot_start_time', str(int(time.time())))

PERMISSIONS = {
    'check_user': 'Проверка пользователя (/check)',
    'user_info': 'Информация о пользователе (/user)',
    'add_days': 'Выдача дней (/add_days)',
    'remove_days': 'Забирание дней (/remove_days)',
    'block_user': 'Блокировка (/block)',
    'unblock_user': 'Разблокировка (/unblock)',
    'announce': 'Рассылка',
    'manage_keys': 'Управление ключами',
    'manage_users': 'Управление пользователями',
    'admin_stats': 'Статистика бота',
    'admin_panel': 'Доступ к админ-панели',
    'view_logs': 'Просмотр логов',
    'manage_admins': 'Управление админами',
}

ROLE_PRESETS = {
    'owner': {
        'name': '👑 Владелец',
        'permissions': {p: True for p in PERMISSIONS}
    },
    'senior': {
        'name': '⭐ Старший админ',
        'permissions': {
            'check_user': True, 'user_info': True, 'add_days': True, 'remove_days': True,
            'block_user': True, 'unblock_user': True, 'announce': True, 'manage_keys': True,
            'manage_admins': False, 'manage_users': True, 'admin_stats': True,
            'admin_panel': True, 'view_logs': True,
        }
    },
    'junior': {
        'name': '🔹 Младший админ',
        'permissions': {
            'check_user': True, 'user_info': True, 'add_days': True, 'remove_days': True,
            'block_user': True, 'unblock_user': True, 'announce': True, 'manage_keys': False,
            'manage_admins': False, 'manage_users': True, 'admin_stats': True,
            'admin_panel': True, 'view_logs': True,
        }
    },
    'support': {
        'name': '🟢 Поддержка',
        'permissions': {
            'check_user': True, 'user_info': True, 'add_days': False, 'remove_days': False,
            'block_user': False, 'unblock_user': False, 'announce': False, 'manage_keys': False,
            'manage_admins': False, 'manage_users': False, 'admin_stats': False,
            'admin_panel': False, 'view_logs': False,
        }
    }
}

def log_admin_action(admin_id, action, target_id=None, details=None, target_name=None, ip_address=None):
    try:
        admin_name = get_user_display_name(admin_id)
        if target_id:
            target_name = target_name or get_user_display_name(target_id)
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO admin_logs 
                (admin_id, admin_name, action, target_id, target_name, details, ip_address, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                admin_id,
                admin_name,
                action,
                target_id,
                target_name,
                details,
                ip_address,
                int(time.time())
            ))
            conn.commit()
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)
    except Exception as e:
        print(f"[log_admin_action] Ошибка: {e}")

def get_subscription_link(user_id):
    if is_blocked(user_id):
        return None
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT token, is_frozen FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        if not result:
            return None
        
        token, is_frozen = result
        
        if is_frozen == 1:
            return None
        
        if token:
            base_url = get_bot_base_url()
            return f"{base_url}/sub/{token}"
        
        # Если токен ещё не сгенерирован, создаем его безопасным для SQLite способом
        token = None
        for _ in range(5):
            candidate = generate_subscription_token()
            try:
                cur.execute(
                    "UPDATE users SET token = %s WHERE user_id = %s AND token IS NULL", 
                    (candidate, user_id)
                )
                conn.commit()
                
                # Проверяем успешность записи токена
                cur.execute("SELECT token FROM users WHERE user_id = %s", (user_id,))
                res = cur.fetchone()
                if res and res[0]:
                    token = res[0]
                    break
            except Exception as e:
                conn.rollback()
                if 'unique' in str(e).lower():
                    # При коллизии уникального токена пробуем еще раз
                    continue
                raise
                
        if not token:
            return None
            
        base_url = get_bot_base_url()
        return f"{base_url}/sub/{token}"
    except Exception as e:
        print(f"[get_subscription_link] Ошибка: {e}")
        return None
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

def get_user_display_name_cached(user_id):
    current_time = int(time.time())
    
    with _user_name_cache_lock:
        cached = _user_name_cache.get(user_id, {})
        if cached.get('timestamp', 0) > current_time - USER_NAME_CACHE_TTL:
            return cached.get('name', str(user_id))
    
    try:
        chat = bot.get_chat(user_id)
        if chat.username:
            name = f"@{chat.username}"
        else:
            name = chat.first_name or ''
            if chat.last_name:
                name += ' ' + chat.last_name
            name = name.strip() or str(user_id)
    except Exception as e:
        print(f"[get_user_display_name_cached] Ошибка для {user_id}: {e}")
        name = str(user_id)
    
    with _user_name_cache_lock:
        _user_name_cache[user_id] = {
            'name': name,
            'timestamp': current_time
        }
    
    return name

def get_bot_username():
    global _bot_username
    with _bot_username_lock:
        if not _bot_username:
            try:
                _bot_username = bot.get_me().username
            except Exception as e:
                print(f"[get_bot_username] Ошибка: {e}")
                return "WSVPN_Bobot"
        return _bot_username

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Основная таблица пользователей
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                subscription_end INTEGER,
                notified_3days INTEGER DEFAULT 0,
                last_activity INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                token TEXT UNIQUE,
                username TEXT,
                telegram_id BIGINT,
                notified_expired INTEGER DEFAULT 0,
                is_frozen INTEGER DEFAULT 0,
                frozen_days_left INTEGER DEFAULT 0,
                frozen_at INTEGER DEFAULT 0
            )
        """)
        
        # Таблица администраторов
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                user_id BIGINT PRIMARY KEY, 
                role TEXT DEFAULT 'junior', 
                permissions TEXT, 
                added_by BIGINT, 
                added_at INTEGER
            )
        """)
        
        # Таблица рефералов с автоинкрементом id
        cur.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id SERIAL PRIMARY KEY, 
                referrer_id BIGINT, 
                referred_id BIGINT, 
                reward_date INTEGER, 
                rewarded INTEGER DEFAULT 0, 
                referrer_subscribed INTEGER DEFAULT 0, 
                referred_subscribed INTEGER DEFAULT 0, 
                UNIQUE(referrer_id, referred_id)
            )
        """)
        
        # Логи админов
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id SERIAL PRIMARY KEY, 
                admin_id BIGINT NOT NULL, 
                admin_name TEXT, 
                action TEXT NOT NULL, 
                target_id BIGINT, 
                target_name TEXT, 
                details TEXT, 
                ip_address TEXT, 
                created_at INTEGER NOT NULL
            )
        """)
        
        # Общие настройки
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, 
                value TEXT
            )
        """)
        
        # Каналы
        cur.execute("""
            CREATE TABLE IF NOT EXISTS broadcast_channels (
                id SERIAL PRIMARY KEY, 
                channel_id BIGINT NOT NULL UNIQUE, 
                channel_name TEXT, 
                enabled INTEGER DEFAULT 1, 
                added_by BIGINT, 
                added_at INTEGER
            )
        """)

        # --- НОВАЯ СТРУКТУРИРОВАННАЯ ТАБЛИЦА ДЛЯ КОНФИГОВ/КЛЮЧЕЙ ПОДПИСКИ ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS subscription_keys (
                id SERIAL PRIMARY KEY,
                key_value TEXT UNIQUE NOT NULL,
                created_at INTEGER
            )
        """)

        # Инициализация первичных данных
        owner_perms = json.dumps({p: True for p in PERMISSIONS})
        cur.execute("""
            INSERT INTO admins (user_id, role, permissions) 
            VALUES (%s, %s, %s) 
            ON CONFLICT (user_id) DO NOTHING
        """, (ADMIN_ID, 'owner', owner_perms))
        
        cur.execute("""
            INSERT INTO settings (key, value) 
            VALUES ('maintenance_mode', '0') 
            ON CONFLICT (key) DO NOTHING
        """)
        
        # === ВСТАВЛЯТЬ СЮДА ===
        # --- АВТОМАТИЧЕСКАЯ МИГРАЦИЯ: Добавляем колонку шифрования для пользователей ---
        try:
            cur.execute("ALTER TABLE users ADD COLUMN encryption_enabled INTEGER DEFAULT 1")
            conn.commit()
            print("[db] ✅ Колонка encryption_enabled успешно проверена/добавлена")
        except Exception:
            # Если колонка уже создана, SQLite/Postgres вызовет ошибку, которую мы просто игнорируем
            pass
        # ======================

        conn.commit()
        print("[db] ✅ Таблицы проверены")
    except Exception as e:
        print(f"[db] ❌ Ошибка инициализации таблиц: {e}")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

def get_setting(key, default=""):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT value FROM settings WHERE key = %s", (key,))
        row = cur.fetchone()
        return row[0] if row else default
    except:
        return default
    finally:
        return_db_connection(conn)

def set_setting(key, value):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Универсальный синтаксис UPSERT, который работает и на PostgreSQL, и на SQLite
        cur.execute("""
            INSERT INTO settings (key, value) 
            VALUES (%s, %s) 
            ON CONFLICT (key) 
            DO UPDATE SET value = EXCLUDED.value
        """, (key, value))
        conn.commit()
    except Exception as e:
        print(f"[set_setting] Ошибка: {e}")
    finally:
        return_db_connection(conn)

def get_setting_bool(key, default=False):
    val = get_setting(key, "1" if default else "0")
    return val == "1"

# ==================== БЛОКИРОВКА ТЕХНИЧЕСКОГО ОБСЛУЖИВАНИЯ ====================

# ==================== БЛОКИРОВКА ТЕХНИЧЕСКОГО ОБСЛУЖИВАНИЯ ====================

@bot.message_handler(func=lambda m: is_maintenance_active() and not is_admin(m.from_user.id))
def maintenance_block_message(message):
    text = (
        "🛠 *Техническое обслуживание*\n\n"
        "В данный момент проводятся профилактические работы.\n"
        "Бот временно недоступен для обычных пользователей.\n\n"
        "⏳ Пожалуйста, зайдите в приложение и воспользуйтесь ботом позже!"
    )
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: is_maintenance_active() and not is_admin(call.from_user.id))
def maintenance_block_callback(call):
    bot.answer_callback_query(
        call.id, 
        "🛠 Бот находится на техническом обслуживании. Операции временно недоступны.", 
        show_alert=True
    )

# ==============================================================================

def is_blocked(user_id):
    if user_id == ADMIN_ID:
        return False
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT is_blocked FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        return result[0] == 1 if result else False
    except:
        return False
    finally:
        return_db_connection(conn)

def is_subscribed(user_id):
    return True # Считаем, что все подписаны для тестирования

@bot.callback_query_handler(func=lambda call: call.data == "admin_add_ref_btn")
def callback_admin_add_ref_prompt(call):
    if not is_admin(call.from_user.id): return
    bot.send_message(call.message.chat.id, "Чтобы накрутить рефералов, используйте команду:\n`/add_ref ID КОЛИЧЕСТВО`", parse_mode="Markdown")
    bot.answer_callback_query(call.id)

def is_admin(user_id):
    if user_id == ADMIN_ID:
        return True
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM admins WHERE user_id = %s", (user_id,))
        return cur.fetchone() is not None
    except:
        return False
    finally:
        return_db_connection(conn)

def has_permission(user_id, permission):
    if user_id == ADMIN_ID:
        return True
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT permissions FROM admins WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if row:
            perms = json.loads(row[0])
            return perms.get(permission, False)
        return False
    except:
        return False
    finally:
        return_db_connection(conn)

# ==================== КАНАЛЫ УПРАВЛЕНИЯ АДМИНИСТРАТОРА (BOT) ====================

@bot.message_handler(commands=['admin'])
def cmd_admin(message):
    update_activity()
    user_id = message.from_user.id
    if not is_admin(user_id):
        return
    bot.reply_to(
        message,
        "👑 *Панель управления администратора*\n\nВыберите нужный раздел из меню ниже:",
        parse_mode="Markdown",
        reply_markup=admin_menu()
    )

def admin_menu():
    kb = types.InlineKeyboardMarkup(row_width=2)
    m_mode = is_maintenance_active()
    m_text = "🔴 Выключить тех. работы" if m_mode else "🛠 Включить тех. работы"
    
    # Считываем текущее глобальное состояние шифрования из настроек
    g_crypt = get_setting("global_encryption", "1") == "1"
    crypt_text = "🔒 Шифр для всех: ВКЛ" if g_crypt else "🔓 Шифр для всех: ВЫКЛ"
    
    kb.add(
        types.InlineKeyboardButton("📢 Рассылка в ЛС", callback_data="admin_announce"),
        types.InlineKeyboardButton("👥 Пользователи", callback_data="admin_manage_users")
    )
    kb.add(
        types.InlineKeyboardButton("🔑 Ключи", callback_data="admin_keys"),
        types.InlineKeyboardButton("👥 Накрутить реф.", callback_data="admin_add_ref_btn")
    )
    kb.add(
        types.InlineKeyboardButton(m_text, callback_data="toggle_maintenance"),
        types.InlineKeyboardButton(crypt_text, callback_data="toggle_global_crypt")
    )
    kb.add(
        types.InlineKeyboardButton("📋 Логи", callback_data="admin_view_logs"),
        types.InlineKeyboardButton("❌ Закрыть панель", callback_data="admin_back")
    )
    return kb

@bot.callback_query_handler(func=lambda call: call.data == "toggle_global_crypt")
def callback_toggle_global_crypt(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
        
    current = get_setting("global_encryption", "1")
    new_state = "0" if current == "1" else "1"
    set_setting("global_encryption", new_state)
    
    log_admin_action(user_id, f"Изменил глобальное шифрование для всех на: {new_state}")
    
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=admin_menu())
    except:
        pass
        
    status = "АКТИВИРОВАНО" if new_state == "1" else "ДЕАКТИВИРОВАНО"
    bot.answer_callback_query(call.id, f"🔒 Глобальное шифрование подписок {status}!", show_alert=True)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_maintenance")
def callback_toggle_maintenance(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    current = "1" if is_maintenance_active() else "0"
    new_state = "1" if current == "0" else "0"
    
    # Записываем значение и в БД, и в кэш RAM
    set_maintenance_mode(new_state)
    log_admin_action(user_id, f"Изменил режим тех. работ на: {new_state}")
    
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=admin_menu())
    except:
        pass
    
    status = "ВКЛЮЧЕН" if new_state == "1" else "ВЫКЛЮЧЕН"
    bot.answer_callback_query(call.id, f"🛠 Режим тех. обслуживания {status}!", show_alert=True)

@bot.message_handler(commands=['add_days'])
def cmd_add_days(message):
    update_activity()
    admin_id = message.from_user.id
    
    # Проверка, является ли отправитель администратором и есть ли у него нужное право
    if not is_admin(admin_id) or not has_permission(admin_id, 'add_days'):
        return

    parts = message.text.split()
    if len(parts) < 3:
        bot.reply_to(
            message, 
            "❌ Неверный формат!\nИспользуйте: `/add_days ID_ИЛИ_USERNAME КОЛИЧЕСТВО_ДНЕЙ`\n\nПример: `/add_days @username 30`", 
            parse_mode="Markdown"
        )
        return

    target_str = parts[1].strip()
    days_str = parts[2].strip()

    # Проверка корректности введенных дней
    try:
        days = int(days_str)
        if days <= 0:
            raise ValueError
    except ValueError:
        bot.reply_to(message, "❌ Количество дней должно быть целым положительным числом.")
        return

    # Поиск ID пользователя по введенной строке (ID или @username)
    target_id = find_user_id(target_str)
    if not target_id:
        bot.reply_to(message, f"❌ Пользователь `{target_str}` не найден в базе данных бота.", parse_mode="Markdown")
        return

    conn = get_db_connection()
    cur = conn.cursor()
    current_time = int(time.time())
    
    try:
        cur.execute("SELECT subscription_end, is_frozen, frozen_days_left FROM users WHERE user_id = %s", (target_id,))
        row = cur.fetchone()
        if not row:
            bot.reply_to(message, "❌ Пользователь не найден в таблице users.")
            return

        subscription_end, is_frozen, frozen_days_left = row

        if is_frozen == 1:
            # Если подписка заморожена, прибавляем дни к сохраненному остатку заморозки
            new_frozen = (frozen_days_left or 0) + days
            cur.execute("UPDATE users SET frozen_days_left = %s WHERE user_id = %s", (new_frozen, target_id))
            details_msg = f"Добавил {days} дн. к замороженной подписке"
            expire_str = f"Заморожена (останется {new_frozen} дн.)"
        else:
            # Если активна или истекла, сдвигаем конечную дату относительно текущего момента или даты окончания
            base_time = max(current_time, subscription_end or 0)
            new_end = base_time + days * 24 * 60 * 60
            cur.execute("""
                UPDATE users 
                SET subscription_end = %s, notified_3days = 0, notified_expired = 0 
                WHERE user_id = %s
            """, (new_end, target_id))
            details_msg = f"Добавил {days} дн. подписки"
            expire_str = datetime.fromtimestamp(new_end).strftime("%d.%m.%Y в %H:%M")

        conn.commit()
        clear_user_cache(target_id)
        
        # Запись действия в лог администратора
        log_admin_action(admin_id, details_msg, target_id=target_id)
        
        bot.reply_to(
            message, 
            f"✅ Успешно!\n👤 Пользователю `{target_str}` (ID: `{target_id}`) добавлено `{days}` дней.\n📅 Новая подписка до: `{expire_str}`", 
            parse_mode="Markdown"
        )

        # Отправка уведомления пользователю
        try:
            if is_frozen == 1:
                bot.send_message(
                    target_id, 
                    f"🎁 Администратор увеличил вашу замороженную подписку на {days} дней!\n"
                    f"Она останется замороженной до тех пор, пока вы не активируете её в меню."
                )
            else:
                bot.send_message(
                    target_id, 
                    f"🎉 Ваша подписка продлена на {days} дней администратором!\n📅 Действительна до: {expire_str}"
                )
        except Exception as e:
            print(f"[cmd_add_days] Не удалось отправить сообщение пользователю {target_id}: {e}")

    except Exception as e:
        print(f"[cmd_add_days] Ошибка: {e}")
        bot.reply_to(message, "❌ Произошла непредвиденная ошибка при изменении подписки в базе данных.")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "admin_back_panel")
def callback_admin_back_panel(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    try:
        bot.edit_message_text(
            "👑 *Панель управления администратора*\n\nВыберите нужный раздел из меню ниже:",
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=admin_menu()
        )
    except:
        pass
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_keys")
def callback_admin_keys(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_add_keys_bot")
def callback_add_keys_bot(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    msg = bot.send_message(
        call.message.chat.id,
        "🔑 *Добавление ключей в базу подписок*\n\n"
        "Отправьте мне список VLESS/VMESS/Trojan/SS конфигураций. \n"
        "Вы можете вставить как одну, так и несколько ссылок одновременно (каждую с новой строки):",
        parse_mode="Markdown"
    )
    bot.register_next_step_handler(msg, process_admin_add_keys_bot)
    bot.answer_callback_query(call.id)

def process_admin_add_keys_bot(message):
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'manage_keys'):
        bot.reply_to(message, "⛔️ Нет прав")
        return
    
    text = message.text
    if not text:
        bot.reply_to(message, "❌ Текст сообщения пуст. Операция отменена.")
        return
    
    new_keys = [line.strip() for line in text.split('\n') if line.strip()]
    if not new_keys:
        bot.reply_to(message, "❌ Валидных ключей не найдено. Операция отменена.")
        return
    
    current_keys = get_subscription_keys_from_db()
    # ПОРЯДОК СОХРАНЕН: используем dict.fromkeys вместо неупорядоченного set()
    all_keys = list(dict.fromkeys(current_keys + new_keys))
    save_subscription_keys_to_db(all_keys)
    
    log_admin_action(user_id, "Добавил ключи через бота", details=f"Добавлено: {len(new_keys)} ключей")
    bot.reply_to(message, f"✅ Успешно импортировано и сохранено {len(new_keys)} ключей в базу подписок!")

@bot.callback_query_handler(func=lambda call: call.data == "admin_keys_clear_all")
def callback_keys_clear_all(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    save_subscription_keys_to_db([])
    log_admin_action(user_id, "Очистил все ключи подписки")
    bot.answer_callback_query(call.id, "🗑️ Все ключи успешно удалены из базы", show_alert=True)
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_keys_clean_dead")
def callback_keys_clean_dead(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    keys = get_subscription_keys_from_db()
    cleaned = [k for k in keys if k.startswith(("vless://", "vmess://", "trojan://", "ss://"))]
    save_subscription_keys_to_db(cleaned)
    
    removed = len(keys) - len(cleaned)
    log_admin_action(user_id, "Очистил нерабочие ключи подписки", details=f"Удалено: {removed} шт.")
    bot.answer_callback_query(call.id, f"🧹 Удалено {removed} нерабочих ключей!", show_alert=True)
    show_keys_menu(user_id, call.message.chat.id, call.message.message_id)
    
@bot.callback_query_handler(func=lambda call: call.data == "admin_sub_keys_load")
def callback_sub_keys_load(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    keys = get_subscription_keys_from_db()
    if not keys:
        bot.answer_callback_query(call.id, "📭 В базе пока нет ключей подписки", show_alert=True)
        return
        
    text = "📋 *Список ключей в базе подписки:*\n\n" + "\n\n".join(keys)
    if len(text) > 4000:
        bio = io.BytesIO(("\n".join(keys)).encode('utf-8'))
        bio.name = "subscription_keys.txt"
        bot.send_document(call.message.chat.id, bio, caption="📋 Файл со всеми ключами подписки:")
        bot.answer_callback_query(call.id)
    else:
        bot.send_message(call.message.chat.id, text, parse_mode="Markdown")
        bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_view_logs")
def callback_view_logs(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    _show_admin_logs(call)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_announce")
def callback_announce_menu(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        types.InlineKeyboardButton("📨 В ЛС всем пользователям", callback_data="announce_type_dm"),
        types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel")
    )
    try:
        bot.edit_message_text(
            "📢 *Выберите тип рассылки:*",
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb
        )
    except:
        pass
    bot.answer_callback_query(call.id)

@bot.message_handler(commands=['add_ref'])
def cmd_add_ref_manual(message):
    admin_id = message.from_user.id
    # Проверка на админа
    if not is_admin(admin_id):
        return

    parts = message.text.split()
    if len(parts) < 3:
        bot.reply_to(message, "❌ Ошибка! Формат: `/add_ref ID_ПОЛЬЗОВАТЕЛЯ КОЛИЧЕСТВО`", parse_mode="Markdown")
        return

    try:
        target_id = int(parts[1])
        amount = int(parts[2])
        if amount <= 0: raise ValueError
    except:
        bot.reply_to(message, "❌ Введите корректный ID и число больше 0")
        return

    conn = get_db_connection()
    cur = conn.cursor()
    current_time = int(time.time())
    added_successfully = 0

    try:
        # Проверяем, существует ли пользователь
        cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
        user_row = cur.fetchone()
        if not user_row:
            bot.reply_to(message, "❌ Пользователь с таким ID не найден в базе.")
            return

        sub_end = user_row[0] or current_time
        new_sub_end = max(current_time, sub_end) + (amount * 3 * 24 * 60 * 60)

        # 1. Обновляем подписку
        cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0, notified_expired = 0 WHERE user_id = %s", 
                   (new_sub_end, target_id))

        # 2. Добавляем фиктивные записи в таблицу рефералов (чтобы в статистике тоже отображалось)
        for _ in range(amount):
            fake_ref_id = random.randint(1000000, 999999999) # Генерируем случайный ID реферала
            try:
                cur.execute("""
                    INSERT INTO referrals (referrer_id, referred_id, reward_date, rewarded, referrer_subscribed, referred_subscribed) 
                    VALUES (%s, %s, %s, 1, 1, 1)
                """, (target_id, fake_ref_id, current_time, ))
                added_successfully += 1
            except:
                continue # Если вдруг ID совпал, просто пропустим
        
        conn.commit()
        
        log_admin_action(admin_id, f"Накрутил {amount} рефералов", target_id=target_id)
        
        bot.reply_to(message, f"✅ Успешно!\n👤 Пользователю `{target_id}` накручено `{added_successfully}` рефералов.\n📅 Подписка продлена на `{added_successfully * 3}` дней.", parse_mode="Markdown")
        
        try:
            bot.send_message(target_id, f"🎁 Администратор начислил вам бонус!\n✨ +{added_successfully} рефералов и +{added_successfully * 3} дней подписки.")
        except: pass

    except Exception as e:
        print(f"[add_ref] Ошибка: {e}")
        bot.reply_to(message, f"❌ Произошла ошибка при накрутке")
    finally:
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "announce_type_dm")
def callback_announce_dm(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    with _cache_lock:
        announce_data[user_id] = {
            'type': 'dm',
            'timestamp': int(time.time())
        }
    
    msg = bot.send_message(
        call.message.chat.id,
        "📢 *Режим рассылки в ЛС*\n\nОтправьте текст, картинку или видео для рассылки всем пользователям.",
        parse_mode="Markdown"
    )
    bot.register_next_step_handler(msg, admin_announce_text)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_manage_users")
def callback_admin_manage_users(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users ORDER BY user_id")
        users = [row[0] for row in cur.fetchall()]
    finally:
        return_db_connection(conn)
    
    with _cache_lock:
        manage_cache[user_id] = {
            'users': users,
            'filter': 'all',
            'timestamp': int(time.time())
        }
    
    kb = build_user_list_keyboard(users, 0, 'all')
    try:
        bot.edit_message_text(
            f"👥 Пользователи ({len(users)}):",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=kb
        )
    except:
        pass
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "admin_back")
def callback_admin_back(call):
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except:
        pass
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("usr_"))
def callback_user_action(call):
    admin_id = call.from_user.id
    if not is_admin(admin_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return

    parts = call.data.split('_')
    if len(parts) < 3:
        bot.answer_callback_query(call.id, "❌ Неверный формат callback")
        return
        
    action = parts[1]
    try:
        target_id = int(parts[2])
    except ValueError:
        bot.answer_callback_query(call.id, "❌ Ошибка парсинга ID")
        return

    conn = get_db_connection()
    cur = conn.cursor()
    current_time = int(time.time())
    try:
        if action == "prolong":
            days = int(parts[3])
            cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
            row = cur.fetchone()
            if row:
                sub_end = max(current_time, row[0])
                new_end = sub_end + days * 24 * 60 * 60
                cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0, notified_expired = 0 WHERE user_id = %s", (new_end, target_id))
                conn.commit()
                log_admin_action(admin_id, f"Продлил подписку на {days} дн.", target_id=target_id)
                bot.answer_callback_query(call.id, f"✅ Добавлено {days} дней")
                try:
                    bot.send_message(target_id, f"🎉 Администратор продлил вашу подписку на {days} дней!")
                except: pass
        elif action == "remdays":
            days = int(parts[3])
            cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (target_id,))
            row = cur.fetchone()
            if row:
                new_end = max(0, row[0] - days * 24 * 60 * 60)
                cur.execute("UPDATE users SET subscription_end = %s WHERE user_id = %s", (new_end, target_id))
                conn.commit()
                log_admin_action(admin_id, f"Списал {days} дн. подписки", target_id=target_id)
                bot.answer_callback_query(call.id, f"✅ Списано {days} дней")
                try:
                    bot.send_message(target_id, f"⚠️ С вашей подписки списано {days} дней.")
                except: pass
        elif action == "givesub":
            new_end = current_time + 30 * 24 * 60 * 60
            cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0, notified_expired = 0, is_frozen = 0, frozen_days_left = 0 WHERE user_id = %s", (new_end, target_id))
            conn.commit()
            log_admin_action(admin_id, "Выдал подписку на 30 дней", target_id=target_id)
            bot.answer_callback_query(call.id, "✅ Подписка выдана на 30 дней")
            try:
                bot.send_message(target_id, "🎉 Вам выдана подписка на 30 дней!")
            except: pass
        elif action == "remsub":
            cur.execute("UPDATE users SET subscription_end = 0, is_frozen = 0, frozen_days_left = 0 WHERE user_id = %s", (target_id,))
            conn.commit()
            log_admin_action(admin_id, "Аннулировал подписку", target_id=target_id)
            bot.answer_callback_query(call.id, "✅ Подписка аннулирована")
            try:
                bot.send_message(target_id, "⚠️ Ваша подписка была аннулирована администратором.")
            except: pass
        elif action == "block":
            cur.execute("UPDATE users SET is_blocked = 1 WHERE user_id = %s", (target_id,))
            conn.commit()
            log_admin_action(admin_id, "Заблокировал пользователя", target_id=target_id)
            bot.answer_callback_query(call.id, "🔒 Пользователь заблокирован")
            try:
                bot.send_message(target_id, "🚫 Вы были заблокированы администратором.")
            except: pass
        elif action == "unblock":
            cur.execute("UPDATE users SET is_blocked = 0 WHERE user_id = %s", (target_id,))
            conn.commit()
            log_admin_action(admin_id, "Разблокировал пользователя", target_id=target_id)
            bot.answer_callback_query(call.id, "🔓 Пользователь разблокирован")
            try:
                bot.send_message(target_id, "🔓 Вы были разблокированы администратором.")
            except: pass
    finally:
        return_db_connection(conn)

    clear_user_cache(target_id)
    _refresh_user_card(call, target_id, admin_id)

# ==============================================================================

def build_user_list_keyboard(users, page, filter_type='all'):
    kb = types.InlineKeyboardMarkup(row_width=2)
    per_page = 5
    start = page * per_page
    end = start + per_page
    current_time = int(time.time())

    page_users = users[start:end]
    user_data = {}
    if page_users:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            placeholders = ','.join(['%s'] * len(page_users))
            query = """
                SELECT user_id, COALESCE(subscription_end, 0), COALESCE(is_blocked, 0) 
                FROM users WHERE user_id IN ({})
            """.format(placeholders)
            cur.execute(query, tuple(page_users))
            user_data = {row[0]: row for row in cur.fetchall()}
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)

    for uid in page_users:
        row = user_data.get(uid)
        if row:
            _, sub_end, blk = row
            if blk == 1:
                icon = "🚫"
            elif sub_end > 0 and sub_end > current_time:
                icon = "🟢"
            else:
                icon = "🔴"
        else:
            icon = "❓"
        admin_icon = "👑 " if is_admin(uid) else ""
        name = get_user_display_name_cached(uid)
        display = f"{icon} {admin_icon}{name}"[:40]
        kb.add(types.InlineKeyboardButton(display, callback_data=f"user_{uid}"))

    nav_row = []
    if page > 0:
        nav_row.append(types.InlineKeyboardButton("◀️ Назад", callback_data=f"page_{page-1}_{filter_type}"))
    if end < len(users):
        nav_row.append(types.InlineKeyboardButton("Вперед ▶️", callback_data=f"page_{page+1}_{filter_type}"))
    if nav_row:
        kb.row(*nav_row)

    kb.row(
        types.InlineKeyboardButton("🟢 Активные", callback_data="filter_active"),
        types.InlineKeyboardButton("🔴 Неактивные", callback_data="filter_inactive")
    )
    kb.row(
        types.InlineKeyboardButton("👑 Админы", callback_data="filter_admins"),
        types.InlineKeyboardButton("📋 Все", callback_data="filter_all")
    )
    kb.row(
        types.InlineKeyboardButton("🔙 Назад в админку", callback_data="admin_back_panel"),
        types.InlineKeyboardButton("❌ Закрыть", callback_data="close_manage")
    )
    return kb

def show_keys_menu(user_id, chat_id, message_id):
    sub_keys = get_subscription_keys_from_db()
    total_issued = int(get_setting('total_keys_issued', '0'))
    
    text = (
        f"🔑 *Управление ключами*\n\n"
        f"📋 *Подписка /sub:* {len(sub_keys)} ключей\n"
        f"🗑️ Выдано ключей: {total_issued}\n\n"
        f"Используйте крипто-инструменты для проверки зашифрованных линков:"
    )
    
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📋 Посмотреть в чате", callback_data="admin_sub_keys_load"),
        types.InlineKeyboardButton("💾 Скачать Бэкап (.txt)", callback_data="admin_sub_keys_backup")
    )
    kb.add(
        types.InlineKeyboardButton("➕ Дописать новые", callback_data="admin_add_keys_bot"),
        types.InlineKeyboardButton("🔄 Перезаписать ВСЕ", callback_data="admin_overwrite_keys_bot")
    )
    # Новые крипто-кнопки
    kb.add(
        types.InlineKeyboardButton("🔓 Дешифратор строк", callback_data="admin_crypto_decrypt"),
        types.InlineKeyboardButton("🔒 Шифратор VLESS", callback_data="admin_crypto_encrypt")
    )
    kb.add(
        types.InlineKeyboardButton("🧹 Очистить нерабочие", callback_data="admin_keys_clean_dead"),
        types.InlineKeyboardButton("🗑️ Очистить ВСЕ", callback_data="admin_keys_clear_all")
    )
    kb.add(
        types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel")
    )
    
    sent = False
    if message_id:
        try:
            bot.edit_message_text(text, chat_id, message_id, parse_mode="Markdown", reply_markup=kb)
            sent = True
        except Exception as e:
            print(f"[show_keys_menu] edit failed: {e}")
    if not sent:
        bot.send_message(chat_id, text, parse_mode="Markdown", reply_markup=kb)

@bot.callback_query_handler(func=lambda call: call.data == "admin_crypto_decrypt")
def callback_crypto_decrypt_prompt(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
        
    msg = bot.send_message(
        call.message.chat.id,
        "🔓 *Инструмент дешифрования*\n\n"
        "Отправьте мне зашифрованную строку подписки:",
        parse_mode="Markdown"
    )
    bot.register_next_step_handler(msg, process_bot_decrypt)
    bot.answer_callback_query(call.id)

def process_bot_decrypt(message):
    user_id = message.from_user.id
    if not is_admin(user_id):
        return
        
    text = message.text
    if not text:
        bot.reply_to(message, "❌ Пустое сообщение. Отменено.")
        return
        
    results = decrypt_any_subscription_input(text)
    if not results:
        bot.reply_to(message, "❌ Не удалось расшифровать данные.")
        return
        
    out = "🔓 *Расшифрованные конфигурации:*\n\n"
    for idx, url in enumerate(results, 1):
        out += f"*{idx}.* `{url}`\n\n"
        
    if len(out) > 4000:
        bio = io.BytesIO(out.encode('utf-8'))
        bio.name = "decrypted_keys.txt"
        bot.send_document(message.chat.id, bio, caption="📋 Результаты дешифрования:")
    else:
        bot.reply_to(message, out, parse_mode="Markdown")


@bot.callback_query_handler(func=lambda call: call.data == "admin_crypto_encrypt")
def callback_crypto_encrypt_prompt(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
        
    msg = bot.send_message(
        call.message.chat.id,
        "🔒 *Инструмент шифрования*\n\n"
        "Отправьте мне сырую ссылку (vless://, vmess://, trojan:// или ss://):",
        parse_mode="Markdown"
    )
    bot.register_next_step_handler(msg, process_bot_encrypt)
    bot.answer_callback_query(call.id)


def process_bot_encrypt(message):
    user_id = message.from_user.id
    if not is_admin(user_id):
        return
        
    url = message.text.strip() if message.text else ""
    if not url:
        bot.reply_to(message, "❌ Отменено.")
        return
        
    if not url.startswith(("vless://", "vmess://", "trojan://", "ss://")):
        bot.reply_to(message, "❌ Ссылка должна начинаться с допустимого протокола (vless://, vmess://, trojan://, ss://).")
        return
        
    encrypted = parse_and_encrypt_vless(url)
    if encrypted:
        bot.reply_to(
            message,
            f"🔒 *Успешно зашифровано:*\n\n`{encrypted}`",
            parse_mode="Markdown"
        )
    else:
        bot.reply_to(message, "❌ Ошибка шифрования.")


@bot.callback_query_handler(func=lambda call: call.data == "admin_sub_keys_backup")
def callback_sub_keys_backup(call):
    user_id = call.from_user.id
    if not is_admin(user_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    keys = get_subscription_keys_from_db()
    if not keys:
        bot.answer_callback_query(call.id, "📭 В базе нет ключей для бэкапа", show_alert=True)
        return
        
    # Формируем и отправляем текстовый бэкап
    bio = io.BytesIO(("\n".join(keys)).encode('utf-8'))
    bio.name = f"wsvpn_backup_{datetime.now().strftime('%d_%m_%Y')}.txt"
    
    bot.send_document(
        call.message.chat.id, 
        bio, 
        caption=f"📦 *Резервная копия ключей подписки*\n👥 Всего ключей: `{len(keys)}` шт.\n📅 Дата: {datetime.now().strftime('%d.%m.%Y %H:%M')}",
        parse_mode="Markdown"
    )
    bot.answer_callback_query(call.id, "✅ Бэкап отправлен!")

@bot.callback_query_handler(func=lambda call: call.data == "admin_overwrite_keys_bot")
def callback_overwrite_keys_bot(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'manage_keys'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    msg = bot.send_message(
        call.message.chat.id,
        "⚠️ *ПОЛНАЯ ПЕРЕЗАПИСЬ БАЗЫ КЛЮЧЕЙ*\n\n"
        "Внимание! Все старые ключи будут полностью стёрты из базы подписок.\n\n"
        "Отправьте мне новый список конфигураций (каждый ключ с новой строки) "
        "или напишите `/cancel` для отмены действия:",
        parse_mode="Markdown"
    )
    bot.register_next_step_handler(msg, process_admin_overwrite_keys_bot)
    bot.answer_callback_query(call.id)

def process_admin_overwrite_keys_bot(message):
    user_id = message.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'manage_keys'):
        bot.reply_to(message, "⛔️ Нет прав")
        return
    
    text = message.text
    if not text or text.strip().lower() == "/cancel":
        bot.reply_to(message, "❌ Действие отменено. База ключей осталась без изменений.")
        return
        
    new_keys = [line.strip() for line in text.split('\n') if line.strip()]
    if not new_keys:
        bot.reply_to(message, "❌ Валидных ключей не найдено. Отменено.")
        return
        
    # Сохраняем исключительно новые, затирая старые
    save_subscription_keys_to_db(new_keys)
    
    log_admin_action(user_id, "Полностью перезаписал ключи через бота", details=f"Новых ключей: {len(new_keys)}")
    bot.reply_to(
        message, 
        f"🔄 *База успешно перезаписана!*\n\n"
        f"Все старые записи стёрты. Теперь в базе содержится `{len(new_keys)}` новых конфигураций.",
        parse_mode="Markdown"
    )

def _show_admin_logs(call):
    user_id = call.from_user.id
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT admin_name, action, target_name, details, created_at
            FROM admin_logs
            ORDER BY created_at DESC
            LIMIT 20
        """)
        logs = cur.fetchall()
    except Exception as e:
        print(f"[logs] Ошибка: {e}")
        bot.send_message(user_id, "❌ Ошибка получения логов")
        return
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    
    if not logs:
        text = "📋 *Логи админов*\n\nПусто"
    else:
        text = "📋 *Последние 20 действий:*\n\n"
        for admin_name, action, target_name, details, created_at in logs:
            time_str = datetime.fromtimestamp(created_at).strftime("%d.%m %H:%M")
            target = f" → {target_name}" if target_name else ""
            text += f"🕐 {time_str} | *{admin_name}* {action}{target}\n"
            if details:
                text += f"  📎 {details}\n"
            text += "\n"
    
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        types.InlineKeyboardButton("🔄 Обновить", callback_data="admin_view_logs"),
        types.InlineKeyboardButton("🔙 Назад", callback_data="admin_back_panel")
    )
    
    try:
        if len(text) > 4000:
            text = text[:3950] + "\n…"
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown", reply_markup=kb)
    except:
        bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)

def admin_announce_text(message):
    user_id = message.from_user.id
    with _cache_lock:
        if user_id not in announce_data:
            return
        data = announce_data.pop(user_id, {})
    
    announce_type = data.get('type', 'dm')
    text = message.text
    caption = message.caption or ''
    
    if announce_type == 'dm':
        if not text and not message.photo and not message.video and not message.document:
            bot.reply_to(message, "❌ Отправьте текст или медиа.")
            return
        
        def do_announce():
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute("SELECT user_id FROM users")
                users = cur.fetchall()
            finally:
                try:
                    cur.close()
                except:
                    pass
                return_db_connection(conn)
            sent = 0
            for (uid,) in users:
                try:
                    if is_blocked(uid):
                        continue
                    if message.photo:
                        bot.send_photo(uid, message.photo[-1].file_id, caption=caption)
                    elif message.video:
                        bot.send_video(uid, message.video.file_id, caption=caption)
                    elif message.document:
                        bot.send_document(uid, message.document.file_id, caption=caption)
                    else:
                        bot.send_message(uid, text)
                    sent += 1
                    time.sleep(0.05)
                except:
                    pass
            log_admin_action(user_id, f"Сделал рассылку в ЛС", details=f"Отправлено: {sent} пользователей")
            try:
                bot.send_message(user_id, f"✅ Отправлено {sent} пользователям")
            except:
                pass
        
        bot.reply_to(message, "⏳ Рассылка запущена в фоне...")
        t = Thread(target=do_announce, daemon=True)
        t.start()
        
    elif announce_type == 'channel':
        channel_id = data.get('channel_id')
        try:
            if message.photo:
                bot.send_photo(channel_id, message.photo[-1].file_id, caption=caption)
            elif message.video:
                bot.send_video(channel_id, message.video.file_id, caption=caption)
            elif message.document:
                bot.send_document(channel_id, message.document.file_id, caption=caption)
            else:
                bot.send_message(channel_id, text)
            log_admin_action(user_id, f"Отправил объявление в канал {channel_id}")
            bot.reply_to(message, "✅ Отправлено")
            try:
                chat_info = bot.get_chat(channel_id)
                ch_name = chat_info.title or str(channel_id)
                add_broadcast_channel(channel_id, ch_name, user_id)
            except:
                pass
        except Exception as e:
            bot.reply_to(message, f"❌ Ошибка: {e}")
            
    elif announce_type == 'all_channels':
        broadcast = get_broadcast_channels()
        all_targets = [(ch_id,) for ch_id, _ in broadcast]
        
        if not all_targets:
            bot.reply_to(message, "❌ Нет каналов для рассылки.")
            return
        sent = 0
        for (ch_id,) in all_targets:
            try:
                if message.photo:
                    bot.send_photo(ch_id, message.photo[-1].file_id, caption=caption)
                elif message.video:
                    bot.send_video(ch_id, message.video.file_id, caption=caption)
                elif message.document:
                    bot.send_document(ch_id, message.document.file_id, caption=caption)
                else:
                    bot.send_message(ch_id, text)
                sent += 1
                time.sleep(0.3)
            except Exception as e:
                print(f"[announce_all] Ошибка отправки в {ch_id}: {e}")
        log_admin_action(user_id, "Рассылка во все каналы", details=f"Отправлено: {sent}")
        bot.reply_to(message, f"✅ Отправлено в {sent} каналов")

def is_user_blocked_bot(user_id):
    current_time = int(time.time())
    
    with _user_blocked_cache_lock:
        cached = _user_blocked_cache.get(user_id, {})
        if cached.get('timestamp', 0) > current_time - USER_BLOCKED_CACHE_TTL:
            return cached.get('blocked', False)
    
    try:
        bot.get_chat(user_id)
        blocked = False
    except Exception as e:
        if 'blocked' in str(e).lower() or 'deactivated' in str(e).lower() or 'user not found' in str(e).lower():
            blocked = True
        else:
            blocked = False
    
    with _user_blocked_cache_lock:
        _user_blocked_cache[user_id] = {
            'blocked': blocked,
            'timestamp': current_time
        }
    
    return blocked

def clear_user_cache(user_id):
    with _user_name_cache_lock:
        if user_id in _user_name_cache:
            del _user_name_cache[user_id]
    with _user_blocked_cache_lock:
        if user_id in _user_blocked_cache:
            del _user_blocked_cache[user_id]

# ==================== ОСНОВНЫЕ ОБРАБОТЧИКИ МЕНЮ ====================

@bot.message_handler(func=lambda m: m.text == "👤 Личный кабинет")
def cabinet(message):
    update_activity()
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    current_time = int(time.time())
    
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(subscription_end, 0), 
                   COALESCE(is_frozen, 0), 
                   COALESCE(frozen_days_left, 0)
            FROM users WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Используйте /start")
            return
        
        subscription_end, is_frozen, frozen_days_left = result
        
        if is_frozen == 1:
            status = "❄️ Заморожена"
            days_left = frozen_days_left
            time_left = f"{days_left} дн"
            expire_date = "Заморожена"
        elif subscription_end > 0 and subscription_end > current_time:
            status = "✅ Активна"
            days_left = (subscription_end - current_time) // (24 * 60 * 60)
            hours_left = ((subscription_end - current_time) // 3600) % 24
            time_left = f"{days_left} дн {hours_left} ч"
            expire_date = datetime.fromtimestamp(subscription_end).strftime("%d.%m.%Y в %H:%M")
        else:
            status = "❌ Не активна"
            time_left = "Закончилась"
            expire_date = "Закончилась"
        
        text = (
            f"👤 *Личный кабинет*\n\n"
            f"🆔 ID: `{user_id}`\n"
            f"📊 Статус: {status}\n"
            f"📅 Подписка до: `{expire_date}`\n"
            f"⏳ Осталось: `{time_left}`"
        )

        kb = types.InlineKeyboardMarkup(row_width=2)
        kb.add(types.InlineKeyboardButton("🔄 Обновить", callback_data="refresh_cabinet"))
        
        bot.reply_to(message, text, parse_mode="Markdown", reply_markup=kb)
        
    except Exception as e:
        print(f"[cabinet] Ошибка: {e}")
        traceback.print_exc()
        bot.reply_to(message, f"❌ Ошибка: {e}")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "refresh_cabinet")
def callback_refresh_cabinet(call):
    user_id = call.from_user.id
    current_time = int(time.time())
    
    clear_user_cache(user_id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(subscription_end, 0), 
                   COALESCE(is_frozen, 0), 
                   COALESCE(frozen_days_left, 0)
            FROM users WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        
        subscription_end, is_frozen, frozen_days_left = result
        
        if is_frozen == 1:
            status = "❄️ Заморожена"
            days_left = frozen_days_left
            time_left = f"{days_left} дн"
            expire_date = "Заморожена"
        elif subscription_end > 0 and subscription_end > current_time:
            status = "✅ Активна"
            days_left = (subscription_end - current_time) // (24 * 60 * 60)
            hours_left = ((subscription_end - current_time) // 3600) % 24
            time_left = f"{days_left} дн {hours_left} ч"
            expire_date = datetime.fromtimestamp(subscription_end).strftime("%d.%m.%Y в %H:%M")
        else:
            status = "❌ Не активна"
            time_left = "Закончилась"
            expire_date = "Закончилась"
        
        text = (
            f"👤 *Личный кабинет*\n\n"
            f"🆔 ID: `{user_id}`\n"
            f"📊 Статус: {status}\n"
            f"📅 Подписка до: `{expire_date}`\n"
            f"⏳ Осталось: `{time_left}`"
        )

        kb = types.InlineKeyboardMarkup(row_width=2)
        kb.add(types.InlineKeyboardButton("🔄 Обновить", callback_data="refresh_cabinet"))
        
        try:
            bot.edit_message_text(
                text,
                call.message.chat.id,
                call.message.message_id,
                parse_mode="Markdown",
                reply_markup=kb
            )
        except:
            bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)
        
        bot.answer_callback_query(call.id, "✅ Обновлено!")
        
    except Exception as e:
        print(f"[refresh_cabinet] Ошибка: {e}")
        bot.answer_callback_query(call.id, "❌ Ошибка")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.message_handler(func=lambda m: m.text == "📡 Моя подписка")
def my_subscription(message):
    update_activity()
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    current_time = int(time.time())
    
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    if not is_subscribed(user_id):
        bot.reply_to(message, "⚠️ Подпишитесь на канал.", reply_markup=subscribe_button())
        return
    
    clear_user_cache(user_id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COALESCE(subscription_end, 0), 
                   COALESCE(is_frozen, 0), 
                   COALESCE(frozen_days_left, 0)
            FROM users WHERE user_id = %s
        """, (user_id,))
        result = cur.fetchone()
        if not result:
            bot.reply_to(message, "❌ Не зарегистрированы. /start")
            return
        
        subscription_end, is_frozen, frozen_days_left = result
        
        # Если подписка заморожена
        if is_frozen == 1:
            text = (
                f"📡 <b>Моя подписка</b>\n\n"
                f"❄️ <b>Подписка заморожена</b>\n\n"
                f"⏳ Сохранено дней: <b>{frozen_days_left}</b>\n\n"
                f"Нажмите кнопку ниже чтобы разморозить.\n"
                f"Будет сгенерирован новый токен подписки.\n\n"
                f"💬 Поддержка: {SUPPORT}"
            )
            kb = types.InlineKeyboardMarkup()
            kb.add(types.InlineKeyboardButton(
                "🔥 Разморозить подписку",
                callback_data="unfreeze_sub"
            ))
            bot.reply_to(message, text, parse_mode="HTML", reply_markup=kb)
            return
        
        link = get_subscription_link(user_id) if subscription_end > 0 and subscription_end > current_time else None
        days_left = (subscription_end - current_time) // (24 * 60 * 60) if subscription_end > 0 and subscription_end > current_time else 0

        if subscription_end > 0 and subscription_end > current_time:
            status_text = f"✅ Активна\n⏳ Осталось: <b>{days_left}</b> дн."
        else:
            status_text = "❌ Не активна\n\nДля продления обратитесь к администратору."

        text = (
            f"📡 <b>Моя подписка</b>\n\n"
            f"📊 Статус: {status_text}\n\n"
        )
        
        if link:
            text += (
                f"🔗 <b>Ваша личная ссылка:</b>\n<code>{link}</code>\n\n"
            )
        
        text += f"💬 Поддержка: {SUPPORT}"

        kb = types.InlineKeyboardMarkup(row_width=1)
        
        if link:
            kb.add(types.InlineKeyboardButton("📋 Копировать ссылку", callback_data=f"copy_link_{user_id}"))
            kb.add(types.InlineKeyboardButton("🤖 Скачать для Android", url="https://github.com/VSd223/WSVPN/releases/download/V1.0/app-debug.apk"))
            # НОВАЯ КНОПКА СБРОСА ССЫЛКИ ПОЛЬЗОВАТЕЛЕМ
            kb.add(types.InlineKeyboardButton("🔄 Пересоздать мою ссылку", callback_data="reset_my_link"))
            if days_left > 0:
                kb.add(types.InlineKeyboardButton(
                    f"❄️ Заморозить ({days_left} дн.)",
                    callback_data="freeze_sub"
                ))
        
        bot.reply_to(message, text, parse_mode="HTML", disable_web_page_preview=True, reply_markup=kb)
    except Exception as e:
        print(f"[my_subscription] Ошибка: {e}")
        traceback.print_exc()
        bot.reply_to(message, f"❌ Ошибка: {e}")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "reset_my_link")
def callback_reset_my_link(call):
    user_id = call.from_user.id
    bot.answer_callback_query(call.id)
    
    text = (
        "🔄 <b>Пересоздание ссылки подписки</b>\n\n"
        "⚠️ <b>Внимание!</b>\n"
        "🔹 Ваша старая ссылка для импорта в приложение <b>перестанет работать</b>.\n"
        "🔹 Устройства с VPN перестанут обновляться, пока вы не вставите новую ссылку.\n"
        "🔹 Будет сгенерирован новый безопасный ключ доступа.\n\n"
        "Вы действительно хотите перевыпустить ссылку подписки?"
    )
    
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("✅ Да, пересоздать", callback_data="reset_my_link_confirm"),
        types.InlineKeyboardButton("❌ Отмена", callback_data="reset_my_link_cancel")
    )
    
    try:
        bot.edit_message_text(
            text, call.message.chat.id, call.message.message_id,
            parse_mode="HTML", reply_markup=kb
        )
    except:
        bot.send_message(user_id, text, parse_mode="HTML", reply_markup=kb)

@bot.callback_query_handler(func=lambda call: call.data == "reset_my_link_cancel")
def callback_reset_my_link_cancel(call):
    bot.answer_callback_query(call.id, "❌ Сброс отменен")
    # Перенаправляем пользователя обратно в раздел подписки
    my_subscription(call.message)

@bot.callback_query_handler(func=lambda call: call.data == "reset_my_link_confirm")
def callback_reset_my_link_confirm(call):
    user_id = call.from_user.id
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        new_token = generate_subscription_token()
        cur.execute("UPDATE users SET token = %s WHERE user_id = %s", (new_token, user_id))
        conn.commit()
        clear_user_cache(user_id)
        bot.answer_callback_query(call.id, "🔄 Ссылка успешно пересоздана!")
    except Exception as e:
        print(f"[reset_my_link_confirm] Ошибка: {e}")
        bot.answer_callback_query(call.id, "❌ Произошла ошибка при сбросе")
    finally:
        return_db_connection(conn)
        
    # Показываем обновленное окно подписки с новой ссылкой
    my_subscription(call.message)

@bot.callback_query_handler(func=lambda call: call.data == "freeze_sub")
def callback_freeze_sub(call):
    user_id = call.from_user.id
    bot.answer_callback_query(call.id)
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT subscription_end FROM users WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        if not result:
            return
        
        current_time = int(time.time())
        sub_end = result[0]
        days_left = max(0, (sub_end - current_time) // (24 * 60 * 60))
        
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    
    text = (
        f"❄️ *Заморозка подписки*\n\n"
        f"⚠️ *Внимание!*\n\n"
        f"🔹 Текущий токен подписки будет *удалён*\n"
        f"🔹 Сохранится: *{days_left} дней*\n"
        f"🔹 При разморозке сгенерируется *новый токен*\n"
        f"🔹 Старая ссылка в приложении *перестанет работать*\n\n"
        f"Вы уверены?"
    )
    
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("✅ Да, заморозить", callback_data="freeze_confirm"),
        types.InlineKeyboardButton("❌ Отмена", callback_data="freeze_cancel")
    )
    
    try:
        bot.edit_message_text(
            text, call.message.chat.id, call.message.message_id,
            parse_mode="Markdown", reply_markup=kb
        )
    except:
        bot.send_message(user_id, text, parse_mode="Markdown", reply_markup=kb)

@app.route('/admin', methods=['GET', 'POST'])
def web_admin():
    msg = ""
    crypto_result = ""
    
    if request.method == 'POST':
        pwd = request.form.get('password')
        action = request.form.get('action')
        new_keys = request.form.get('keys')
        
        if pwd != WEB_PASSWORD:
            return "❌ Неверный пароль!", 403
            
        # 1. Скачивание бэкапа
        if action == 'backup':
            keys = get_subscription_keys_from_db()
            output = "\n".join(keys)
            return output, 200, {
                'Content-Disposition': 'attachment; filename=wsvpn_backup.txt',
                'Content-Type': 'text/plain; charset=utf-8'
            }
            
        # 2. Сохранение или перезапись ключей
        elif action in ('add', 'overwrite') and new_keys:
            added_list = [k.strip() for k in new_keys.split('\n') if k.strip()]
            if action == 'overwrite':
                save_subscription_keys_to_db(added_list)
                msg = f"🔄 База полностью перезаписана! Установлено {len(added_list)} ключей."
            else:
                current_keys = get_subscription_keys_from_db()
                all_keys = list(dict.fromkeys(current_keys + added_list))
                save_subscription_keys_to_db(all_keys)
                msg = f"✅ Успешно добавлено {len(added_list)} ключей в общую базу!"

        # 3. Дешифрование данных через Веб (БЕЗ ДАТЫ)
        elif action == 'decrypt_tool':
            encrypted_input = request.form.get('encrypted_input', '').strip()
            decoded_items = decrypt_any_subscription_input(encrypted_input)
            if decoded_items:
                crypto_result = "🔓 <b>Результат расшифрования:</b><br><br>"
                for idx, url in enumerate(decoded_items, 1):
                    crypto_result += f"<b>[{idx}] Ссылка:</b><br><code>{url}</code><br><br>"
            else:
                crypto_result = "❌ Не удалось расшифровать. Убедитесь, что ввели корректную зашифрованную строку."

        # 4. Ручное шифрование данных через Веб (БЕЗ ДАТЫ)
        elif action == 'encrypt_tool':
            raw_url = request.form.get('raw_url', '').strip()
            encrypted = parse_and_encrypt_vless(raw_url)
            if encrypted:
                crypto_result = f"🔒 <b>Зашифрованная строка:</b><br><br><textarea style='width:100%; height:80px; background:#222; color:#00FF88; border:1px solid #444; font-family:monospace; padding:8px;' readonly>{encrypted}</textarea>"
            else:
                crypto_result = "❌ Ошибка шифрования. Проверьте правильность формата ссылки."

        # 5. Переключение глобального шифрования из Web
        elif action == 'toggle_global_encryption':
            current = get_setting('global_encryption', '1')
            new_state = '0' if current == '1' else '1'
            set_setting('global_encryption', new_state)
            msg = f"⚙️ Глобальное шифрование подписок изменено на: {'ВКЛЮЧЕНО' if new_state == '1' else 'ВЫКЛЮЧЕНО'}."

    html = f'''
    <html>
        <head>
            <title>WSVPN Admin Panel</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family:sans-serif; background:#121212; color:white; padding:40px; }}
                input, textarea, select, button {{ padding:10px; background:#1e1e1e; color:white; border:1px solid #333; border-radius:5px; margin-top:5px; }}
                button {{ cursor:pointer; font-weight:bold; }}
                .container {{ display: flex; gap: 40px; flex-wrap: wrap; }}
                .box {{ flex: 1; min-width: 300px; background: #1a1a1a; padding: 25px; border-radius: 8px; border: 1px solid #2a2a2a; }}
            </style>
        </head>
        <body>
            <h2>🔑 Управление ключами подписки (Веб-панель)</h2>
            <p style="color: #00FF88; font-weight: bold;">{msg}</p>
            
            <div class="container">
                <!-- Левая колонка: Основная работа с базой -->
                <div class="box">
                    <h3>📁 Импорт и бэкап базы</h3>
                    <form method="post">
                        <label>Пароль доступа:</label><br>
                        <input type="password" name="password" placeholder="Пароль" required style="width:100%;"><br><br>
                        
                        <label>Вставьте конфигурации (с новой строки):</label><br>
                        <textarea name="keys" rows="8" placeholder="vless://..." style="width:100%; font-family:monospace;"></textarea><br><br>
                        
                        <div style="margin-bottom: 20px; background: #252525; padding: 12px; border-radius: 6px;">
                            <input type="radio" id="act_add" name="action" value="add" checked>
                            <label for="act_add" style="cursor: pointer; margin-right:15px;">🟢 Добавить к текущим</label><br>
                            <input type="radio" id="act_overwrite" name="action" value="overwrite">
                            <label for="act_overwrite" style="color: #FF5252; cursor: pointer;">⚠️ Стереть старые и перезаписать</label>
                        </div>
                        
                        <button type="submit" style="width:100%; background:#3F51B5; margin-bottom: 10px;">ВЫПОЛНИТЬ ИЗМЕНЕНИЯ</button>
                        <button type="submit" name="action" value="backup" style="width:100%; background:#4CAF50;">💾 СКАЧАТЬ БЭКАП БАЗЫ (.TXT)</button>
                    </form>
                    <hr style="border:0.5px solid #333; margin: 20px 0;">
                    <h4>Сейчас в БД: <span style="color:#2D54FF;">{len(get_subscription_keys_from_db())}</span> ключей.</h4>
                </div>
                
                <!-- Правая колонка: Крипто-инструменты -->
                <div class="box">
                    <h3>🛠️ Дешифратор и Шифратор (AES-128-ECB)</h3>
                    
                    <!-- Быстрое управление глобальным шифрованием -->
                    <div style="margin-bottom: 25px; background: #252525; padding: 15px; border-radius: 6px; border: 1px solid #3c3c3c;">
                        <p style="margin: 0 0 10px 0; font-weight: bold;">⚙️ Статус шифрования для всех:</p>
                        <form method="post" style="margin: 0;">
                            <input type="hidden" name="password" value="{request.form.get('password', '')}">
                            <input type="hidden" name="action" value="toggle_global_encryption">
                            <button type="submit" style="width: 100%; background: {'#ff9800' if get_setting('global_encryption', '1') == '1' else '#4caf50'}; color: white;">
                                { "🔴 Выключить глобальное шифрование" if get_setting('global_encryption', '1') == '1' else "🟢 Включить глобальное шифрование" }
                            </button>
                        </form>
                    </div>
                    
                    <!-- Форма дешифрования -->
                    <form method="post" style="margin-bottom:25px;">
                        <input type="hidden" name="password" value="{request.form.get('password', '')}">
                        <input type="hidden" name="action" value="decrypt_tool">
                        <label><b>Расшифровать строку или бандл подписки:</b></label><br>
                        <textarea name="encrypted_input" rows="4" placeholder="Вставьте зашифрованный текст..." style="width:100%; font-family:monospace;" required></textarea><br>
                        <button type="submit" style="background:#f44336; margin-top:8px; width:100%;">🔓 Расшифровать данные</button>
                    </form>
                    
                    <!-- Форма шифрования (БЕЗ ДАТЫ) -->
                    <form method="post">
                        <input type="hidden" name="password" value="{request.form.get('password', '')}">
                        <input type="hidden" name="action" value="encrypt_tool">
                        <label><b>Зашифровать сырую ссылку:</b></label><br>
                        <input type="text" name="raw_url" placeholder="vless://..." style="width:100%; font-family:monospace;" required><br>
                        <button type="submit" style="background:#e91e63; margin-top:8px; width:100%;">🔒 Зашифровать в AES</button>
                    </form>
                    
                    <!-- Блок вывода результатов -->
                    {f'<div style="margin-top:20px; background:#222; padding:15px; border-radius:6px; border:1px solid #444; max-height:280px; overflow-y:auto;">{crypto_result}</div>' if crypto_result else ''}
                </div>
            </div>
        </body>
    </html>
    '''
    return html

@app.route('/ping')
def ping(): return "pong", 200

@app.route('/health')
def health(): return "ok", 200

@bot.callback_query_handler(func=lambda call: call.data == "freeze_confirm")
def callback_freeze_confirm(call):
    user_id = call.from_user.id
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT subscription_end FROM users WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        
        current_time = int(time.time())
        sub_end = result[0]
        days_left = max(0, (sub_end - current_time) // (24 * 60 * 60))
        
        cur.execute("""
            UPDATE users SET 
                is_frozen = 1,
                frozen_days_left = %s,
                frozen_at = %s,
                token = NULL,
                subscription_end = 0
            WHERE user_id = %s
        """, (days_left, int(time.time()), user_id))
        conn.commit()
        
        clear_user_cache(user_id)
        
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    
    bot.answer_callback_query(call.id, "❄️ Подписка заморожена!")
    
    try:
        bot.edit_message_text(
            f"❄️ *Подписка заморожена*\n\n⏳ Сохранено: `{days_left}` дней\n\nДля разморозки нажмите кнопку в разделе 📡 *Моя подписка*",
            call.message.chat.id, call.message.message_id,
            parse_mode="Markdown"
        )
    except:
        pass
    
def find_user_id(identifier):
    """Ищет Telegram ID пользователя в БД по числу (ID) или строке (@username)"""
    identifier = identifier.strip()
    if not identifier:
        return None
    if identifier.isdigit():
        return int(identifier)
    
    username = identifier.lstrip('@').lower()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE LOWER(username) = %s", (username,))
        row = cur.fetchone()
        if row:
            return row[0]
    except Exception as e:
        print(f"[find_user_id] Ошибка поиска: {e}")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    return None

@bot.message_handler(commands=['crypt_on', 'crypt_off'])
def cmd_toggle_user_crypt(message):
    admin_id = message.from_user.id
    if not is_admin(admin_id):
        return
        
    command = message.text.split()[0].lower() # /crypt_on или /crypt_off
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(
            message, 
            f"❌ Использование:\n`{command} ID_ПОЛЬЗОВАТЕЛЯ` или `{command} @username`", 
            parse_mode="Markdown"
        )
        return
        
    target_str = parts[1].strip()
    target_id = find_user_id(target_str)
    if not target_id:
        bot.reply_to(message, "❌ Пользователь не найден в базе данных ботом.")
        return
        
    state = 1 if 'crypt_on' in command else 0
    state_text = "ВКЛЮЧЕНО" if state == 1 else "ВЫКЛЮЧЕНО"
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET encryption_enabled = %s WHERE user_id = %s", (state, target_id))
        conn.commit()
        
        log_admin_action(admin_id, f"Изменил статус шифрования на {state_text}", target_id=target_id)
        
        bot.reply_to(
            message, 
            f"👤 Пользователю `{target_id}` успешно *{state_text}* шифрование подписки!", 
            parse_mode="Markdown"
        )
        
        # Уведомляем пользователя
        try:
            if state == 1:
                bot.send_message(target_id, "🔒 Администратор перевел вашу ссылку в зашифрованный режим (для Android-приложения).")
            else:
                bot.send_message(target_id, "🔓 Администратор отключил шифрование для вашей ссылки. Теперь её можно использовать в сторонних VPN-клиентах.")
        except:
            pass
            
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка при изменении настроек в БД: {e}")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data == "freeze_cancel")
def callback_freeze_cancel(call):
    bot.answer_callback_query(call.id, "❌ Отменено")
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except:
        pass

@bot.callback_query_handler(func=lambda call: call.data == "unfreeze_sub")
def callback_unfreeze_sub(call):
    user_id = call.from_user.id
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT frozen_days_left FROM users WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        if not result:
            bot.answer_callback_query(call.id, "❌ Ошибка")
            return
        
        frozen_days = result[0] or 0
        current_time = int(time.time())
        new_sub_end = current_time + frozen_days * 24 * 60 * 60
        new_token = generate_subscription_token()
        
        cur.execute("""
            UPDATE users SET
                is_frozen = 0,
                frozen_days_left = 0,
                frozen_at = 0,
                subscription_end = %s,
                token = %s,
                notified_3days = 0
            WHERE user_id = %s
        """, (new_sub_end, new_token, user_id))
        conn.commit()
        
        clear_user_cache(user_id)
        
        new_link = f"{get_bot_base_url()}/sub/{new_token}"
        
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    
    bot.answer_callback_query(call.id, "🔥 Подписка разморожена!")
    
    text = (
        f"🔥 *Подписка разморожена!*\n\n"
        f"✅ Активна ещё: `{frozen_days}` дней\n"
        f"🔗 Новая ссылка:\n"
        f"{new_link}\n\n"
        f"⚠️ Старая ссылка больше не работает!\n"
        f"Обновите подписку в клиенте."
    )
    
    try:
        bot.edit_message_text(
            text, call.message.chat.id, call.message.message_id,
            parse_mode="Markdown"
        )
    except:
        bot.send_message(user_id, text, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith('copy_link_'))
def callback_copy_link(call):
    user_id = call.from_user.id
    target_id = int(call.data.split('_')[2])

    if user_id != target_id:
        bot.answer_callback_query(call.id, "❌ Это не ваша ссылка.")
        return

    link = get_subscription_link(user_id)
    if not link:
        bot.answer_callback_query(call.id, "❌ Подписка заморожена или недоступна.")
        return

    bot.send_message(
        user_id,
        f"📋 *Ссылка для импорта:*\n\n{link}",
        parse_mode="Markdown"
    )
    bot.answer_callback_query(call.id, "✅ Ссылка отправлена!")

@bot.message_handler(func=lambda m: m.text == "👥 Рефералы")
def referrals(message):
    update_activity()
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cur.fetchone():
            bot.reply_to(message, "❌ Вы не зарегистрированы. Используйте /start")
            return
        cur.execute("SELECT COUNT(*) FROM referrals WHERE referrer_id = %s", (user_id,))
        total = cur.fetchone()[0]
        today_start = int(time.time()) - 24 * 60 * 60
        cur.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = %s AND reward_date > %s",
            (user_id, today_start)
        )
        today = cur.fetchone()[0]
        bot_username = get_bot_username()
        ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
        text = f"👥 *Рефералы*\n\n📊 Всего: {total}\n📅 Сегодня: {today} / 10\n\n🔗 Ссылка: `{ref_link}`\n\n📌 За каждого друга +3 дня."
        bot.reply_to(message, text, parse_mode="Markdown")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.message_handler(func=lambda m: m.text == "🏆 Топ рефералов")
def top_referrals(message):
    update_activity()
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT referrer_id, COUNT(*) FROM referrals GROUP BY referrer_id ORDER BY COUNT(*) DESC LIMIT 10")
        rows = cur.fetchall()
        if not rows:
            bot.reply_to(message, "📭 Нет рефералов.")
            return
        text = "🏆 *Топ рефералов:*\n\n"
        medals = ['🥇', '🥈', '🥉']
        for i, (ref_id, count) in enumerate(rows):
            name = get_user_display_name_cached(ref_id)
            icon = medals[i] if i < 3 else f"{i+1}."
            text += f"{icon} {name} — {count} реф.\n"
        bot.reply_to(message, text, parse_mode="Markdown")
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.message_handler(func=lambda m: m.text == "ℹ️ Стаж бота")
def bot_stats_command(message):
    update_activity()
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    stats = get_bot_stats()
    text = (
        f"📊 *Статистика*\n\n"
        f"⏳ Стаж: {stats['uptime_text']}\n"
        f"👥 Пользователей: {stats['total_users']}\n"
        f"📦 Ключей: {stats['current_keys']}"
    )
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.message_handler(func=lambda m: m.text == "📋 Правила")
def rules(message):
    update_activity()
    if message.chat.type != 'private':
        return
    user_id = message.from_user.id
    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return
    
    text = (
        "⚠️ *Правила использования сети:*\n\n"
        "🛑 *Строго запрещено:*\n"
        "🔹 Использование торрентов и P2P-сетей\n"
        "_(Это приводит к высокой нагрузке на процессоры серверов и их блокировке)_\n\n"
        "🏦 *Ограничения:*\n"
        "🔹 Не использовать для работы с банковскими приложениями\n"
        "_(Запрещено во избежание блокировок за подозрительные финансовые операции)_\n\n"
        f"💬 По всем вопросам: {SUPPORT}"
    )
    bot.reply_to(message, text, parse_mode="Markdown")

@bot.message_handler(func=lambda m: m.text == "❓ Поддержка")
def support(message):
    bot.reply_to(message, f"💬 Поддержка: {SUPPORT}")

@bot.message_handler(commands=['start'])
def cmd_start(message):
    update_activity()
    if message.chat.type != 'private':
        bot.reply_to(message, "⚠️ Бот работает только в личных сообщениях.")
        return

    user_id = message.from_user.id
    current_time = int(time.time())

    if is_blocked(user_id):
        bot.reply_to(message, blocked_message())
        return

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        existing_user = cur.fetchone()
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

    if existing_user:
        if not is_subscribed(user_id):
            bot.reply_to(message, "⚠️ Подпишитесь на канал, чтобы пользоваться ботом.", reply_markup=subscribe_button())
            return
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT last_activity FROM users WHERE user_id = %s", (user_id,))
            result = cur.fetchone()
            if result:
                last_activity = result[0] or 0
                days_since_last = (current_time - last_activity) // (24 * 60 * 60)
                welcome_text = "👋 С возвращением!" if days_since_last >= 3 else "👋 Добро пожаловать!"
                cur.execute("UPDATE users SET last_activity = %s WHERE user_id = %s", (current_time, user_id))
                conn.commit()
                bot.reply_to(message, welcome_text)
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)
        bot.send_message(user_id, "Выберите действие:", reply_markup=main_menu())
        return

    with _captcha_lock:
        if user_id in captcha_sessions:
            session = captcha_sessions[user_id]
            if int(time.time()) - session['timestamp'] < CAPTCHA_TIMEOUT:
                bot.reply_to(
                    message,
                    "⏳ Вы уже проходите капчу. Нажмите кнопку ниже.",
                    reply_markup=types.InlineKeyboardMarkup().add(
                        types.InlineKeyboardButton("✅ Я НЕ РОБОТ", callback_data=f"captcha_verify_{user_id}")
                    )
                )
                return
            else:
                del captcha_sessions[user_id]

    ok, msg = check_subscribe_rate()
    if not ok:
        bot.reply_to(message, f"⚠️ {msg}")
        return

    add_subscribe_record(user_id)

    referrer_id = None
    if message.text:
        parts = message.text.strip().split()
        if len(parts) > 1:
            for part in parts:
                if part.startswith('ref_'):
                    try:
                        ref = int(part[4:])
                        if ref != user_id:
                            referrer_id = ref
                        break
                    except ValueError:
                        continue

    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("✅ Я НЕ РОБОТ", callback_data=f"captcha_verify_{user_id}"))

    msg = bot.reply_to(
        message,
        "🤖 *Пожалуйста, подтвердите, что вы не робот*\n\n"
        "Нажмите кнопку ниже для проверки.\n"
        f"⏱ У вас {CAPTCHA_TIMEOUT//60} минут.",
        parse_mode="Markdown",
        reply_markup=kb
    )

    with _captcha_lock:
        captcha_sessions[user_id] = {
            'timestamp': int(time.time()),
            'message_id': msg.message_id,
            'referrer_id': referrer_id,
            'waiting_for_sub': False
        }

@bot.callback_query_handler(func=lambda call: call.data.startswith('captcha_verify_'))
def callback_captcha_verify(call):
    user_id = int(call.data.split('_')[2])
    if call.from_user.id != user_id:
        bot.answer_callback_query(call.id, "❌ Это не ваша капча.")
        return
    
    with _captcha_lock:
        if user_id not in captcha_sessions:
            bot.answer_callback_query(call.id, "❌ Сессия истекла. Нажмите /start")
            return
        session = captcha_sessions[user_id]
        current_time = int(time.time())
        if current_time - session['timestamp'] > CAPTCHA_TIMEOUT:
            del captcha_sessions[user_id]
            bot.answer_callback_query(call.id, "⏰ Время вышло. Нажмите /start")
            return
    
    try:
        bot.delete_message(call.message.chat.id, session['message_id'])
    except:
        pass
    bot.answer_callback_query(call.id, "✅ Капча пройдена!")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        already_registered = cur.fetchone()
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

    if already_registered:
        with _captcha_lock:
            if user_id in captcha_sessions:
                del captcha_sessions[user_id]
        bot.send_message(user_id, "👋 Вы уже зарегистрированы!")
        bot.send_message(user_id, "Выберите действие:", reply_markup=main_menu())
        return

    if is_subscribed(user_id):
        bot.send_message(user_id, "✅ Подписка подтверждена! Регистрируем вас...")
        with _captcha_lock:
            referrer_id = captcha_sessions.get(user_id, {}).get('referrer_id')
            if user_id in captcha_sessions:
                del captcha_sessions[user_id]
        _register_user(user_id, referrer_id)
    else:
        bot.send_message(
            user_id,
            "⚠️ Подпишитесь на канал, чтобы завершить регистрацию.\n\n"
            "После подписки нажмите кнопку ниже.",
            reply_markup=subscribe_button()
        )
        with _captcha_lock:
            if user_id in captcha_sessions:
                captcha_sessions[user_id]['waiting_for_sub'] = True

@bot.callback_query_handler(func=lambda call: call.data == "check_sub")
def callback_check_sub(call):
    update_activity()
    if call.message.chat.type != 'private':
        bot.answer_callback_query(call.id, "⚠️ Работает только в личных сообщениях.")
        return
    user_id = call.from_user.id
    current_time = int(time.time())
    if is_blocked(user_id):
        bot.answer_callback_query(call.id, "🚫 Вы заблокированы.")
        return
    if is_subscribed(user_id):
        bot.answer_callback_query(call.id, "✅ Подписка подтверждена!")
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except:
            pass
        
        with _captcha_lock:
            if user_id in captcha_sessions and captcha_sessions[user_id].get('waiting_for_sub'):
                conn = get_db_connection()
                cur = conn.cursor()
                try:
                    cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
                    already_registered = cur.fetchone()
                finally:
                    try:
                        cur.close()
                    except:
                        pass
                    return_db_connection(conn)
                
                if already_registered:
                    del captcha_sessions[user_id]
                    bot.send_message(user_id, "👋 Вы уже зарегистрированы!")
                    bot.send_message(user_id, "Выберите действие:", reply_markup=main_menu())
                    return
                
                session = captcha_sessions[user_id]
                del captcha_sessions[user_id]
                bot.send_message(user_id, "✅ Подписка подтверждена! Регистрируем вас...")
                _register_user(user_id, session.get('referrer_id'))
                return
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT referrer_id FROM referrals WHERE referred_id = %s AND rewarded = 0",
                (user_id,)
            )
            pending = cur.fetchone()
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)
        if pending:
            referrer_id = pending[0]
            if is_subscribed(referrer_id):
                conn = get_db_connection()
                cur = conn.cursor()
                try:
                    cur.execute("SELECT subscription_end FROM users WHERE user_id = %s", (referrer_id,))
                    ref_result = cur.fetchone()
                    if ref_result:
                        new_end = ref_result[0] + 3 * 24 * 60 * 60
                        cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0 WHERE user_id = %s", 
                                   (new_end, referrer_id))
                        cur.execute("UPDATE referrals SET rewarded = 1 WHERE referred_id = %s", (user_id,))
                        conn.commit()
                        try:
                            bot.send_message(referrer_id, "🎉 Ваш реферал подтвердил подписку! Вам начислено +3 дня.")
                        except:
                            pass
                finally:
                    try:
                        cur.close()
                    except:
                        pass
                    return_db_connection(conn)
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
            user_exists = cur.fetchone()
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)
        if not user_exists:
            _register_user(user_id, None)
        else:
            bot.send_message(user_id, "👋 Добро пожаловать!")
            bot.send_message(user_id, "Выберите действие:", reply_markup=main_menu())
    else:
        bot.answer_callback_query(call.id, "❌ Вы ещё не подписались на канал!")

def _register_user(user_id, referrer_id=None):
    current_time = int(time.time())
    registered = False
    conn = None
    cur = None
    
    for attempt in range(5):
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
            existing = cur.fetchone()
            
            if existing:
                registered = True
                break
            
            token = generate_subscription_token()
            sub_end = current_time + 7 * 24 * 60 * 60
            
            username = None
            try:
                chat = bot.get_chat(user_id)
                username = chat.username
            except:
                pass
            
            cur.execute("""
                INSERT INTO users (user_id, subscription_end, last_activity, is_blocked, token, username, telegram_id) 
                VALUES (%s, %s, %s, 0, %s, %s, %s)
            """, (user_id, sub_end, current_time, token, username, user_id))
            conn.commit()
            registered = True
            break
        except Exception as e:
            conn.rollback()
            if 'unique' in str(e).lower() and 'token' in str(e).lower():
                print(f"[_register_user] Конфликт токена, попытка {attempt+1}")
                continue
            print(f"[_register_user] Ошибка: {e}")
            break
        finally:
            try:
                if cur:
                    cur.close()
            except:
                pass
            if conn:
                return_db_connection(conn)
    
    if not registered:
        print(f"[_register_user] Не удалось зарегистрировать {user_id}")
        return
    
    if referrer_id:
        success, msg = process_referral(referrer_id, user_id)
        if success:
            try:
                bot.send_message(referrer_id, f"🔔 Новый реферал! Пользователь {get_user_display_name_cached(user_id)} зарегистрировался по вашей ссылке.")
            except:
                pass
    
    try:
        bot.send_message(user_id, "🎉 Добро пожаловать! Вам выдана подписка на 7 дней.")
        bot.send_message(user_id, "Выберите действие:", reply_markup=main_menu())
    except Exception as e:
        print(f"[_register_user] Ошибка отправки приветствия: {e}")

@bot.callback_query_handler(func=lambda call: call.data.startswith('filter_') or 
                             call.data.startswith('page_') or
                             call.data in ('back_to_list', 'close_manage'))
def callback_user_list_nav(call):
    user_id = call.from_user.id
    if not is_admin(user_id) or not has_permission(user_id, 'manage_users'):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
    
    data = call.data
    
    if data == 'close_manage':
        bot.answer_callback_query(call.id)
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except:
            pass
        return
    
    if data == 'back_to_list':
        bot.answer_callback_query(call.id)
        with _cache_lock:
            cached = manage_cache.get(user_id, {})
            users = cached.get('users', [])
            filter_type = cached.get('filter', 'all')
        if not users:
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute("SELECT user_id FROM users ORDER BY user_id")
                users = [row[0] for row in cur.fetchall()]
            finally:
                try:
                    cur.close()
                except:
                    pass
                return_db_connection(conn)
            with _cache_lock:
                manage_cache[user_id] = {
                    'users': users,
                    'filter': 'all',
                    'timestamp': int(time.time())
                }
        kb = build_user_list_keyboard(users, 0, filter_type)
        try:
            bot.edit_message_text(
                f"👥 Пользователи ({len(users)}):",
                call.message.chat.id, call.message.message_id,
                reply_markup=kb
            )
        except:
            pass
        return
    
    if data.startswith('page_'):
        parts = data.split('_')
        if len(parts) < 3:
            bot.answer_callback_query(call.id, "❌ Ошибка формата")
            return
        try:
            page = int(parts[1])
        except ValueError:
            bot.answer_callback_query(call.id, "❌ Ошибка формата")
            return
        filter_type = parts[2] if len(parts) > 2 else 'all'
        with _cache_lock:
            cached = manage_cache.get(user_id, {})
            users = cached.get('users', [])
        if not users:
            bot.answer_callback_query(call.id, "❌ Список устарел")
            return
        kb = build_user_list_keyboard(users, page, filter_type)
        try:
            bot.edit_message_reply_markup(
                call.message.chat.id, call.message.message_id,
                reply_markup=kb
            )
        except:
            pass
        bot.answer_callback_query(call.id)
        return
    
    conn = get_db_connection()
    cur = conn.cursor()
    current_time = int(time.time())
    try:
        if data == 'filter_active':
            cur.execute("""
                SELECT user_id FROM users 
                WHERE is_blocked = 0 AND subscription_end > %s 
                ORDER BY user_id
            """, (current_time,))
            filter_type = 'active'
        elif data == 'filter_inactive':
            cur.execute("""
                SELECT user_id FROM users 
                WHERE is_blocked = 0 AND (subscription_end IS NULL OR subscription_end <= %s)
                ORDER BY user_id
            """, (current_time,))
            filter_type = 'inactive'
        elif data == 'filter_admins':
            cur.execute("""
                SELECT u.user_id FROM users u
                INNER JOIN admins a ON u.user_id = a.user_id
                ORDER BY u.user_id
            """)
            filter_type = 'admins'
        else:
            cur.execute("SELECT user_id FROM users ORDER BY user_id")
            filter_type = 'all'
        
        users = [row[0] for row in cur.fetchall()]
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    
    with _cache_lock:
        manage_cache[user_id] = {
            'users': users,
            'filter': filter_type,
            'timestamp': int(time.time())
        }
    
    kb = build_user_list_keyboard(users, 0, filter_type)
    try:
        bot.edit_message_text(
            f"👥 Пользователи ({len(users)}):",
            call.message.chat.id, call.message.message_id,
            reply_markup=kb
        )
    except:
        pass
    bot.answer_callback_query(call.id)

def _refresh_user_card(call, target_id, admin_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT 
                    COALESCE(subscription_end, 0) as subscription_end,
                    COALESCE(is_blocked, 0) as is_blocked
                FROM users WHERE user_id = %s
            """, (target_id,))
            row = cur.fetchone()
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)

        if not row:
            bot.answer_callback_query(call.id, "❌ Пользователь не найден")
            return

        subscription_end, blk = row
        current_time = int(time.time())
        
        if blk == 1:
            status = "🚫 Заблокирован"
        elif subscription_end > 0 and subscription_end > current_time:
            days_left = (subscription_end - current_time) // 86400
            status = f"🟢 Активен ({days_left} дн)"
        else:
            status = "🔴 Неактивен"

        is_admin_user = is_admin(target_id)
        admin_text = "✅ Да" if is_admin_user else "❌ Нет"
        name = get_user_display_name_cached(target_id)
        
        try:
            chat = bot.get_chat(target_id)
            username = f"@{chat.username}" if chat.username else "❌ Нет юзернейма"
        except:
            username = "❌ Не найден"

        text = f"""👤 *{name}*

🆔 ID: `{target_id}`
👤 Юзернейм: {username}
📊 Статус: {status}
👑 Админ: {admin_text}"""

        kb = types.InlineKeyboardMarkup(row_width=2)
        
        # Исправленные callback_data с префиксом usr_
        if has_permission(admin_id, 'add_days') or admin_id == ADMIN_ID:
            kb.add(types.InlineKeyboardButton("✅ Выдать подписку", callback_data=f"usr_givesub_{target_id}"))
            kb.add(types.InlineKeyboardButton("📅 +30 дн", callback_data=f"usr_prolong_{target_id}_30"))
        
        if has_permission(admin_id, 'remove_days') or admin_id == ADMIN_ID:
            kb.add(types.InlineKeyboardButton("📅 -30 дн", callback_data=f"usr_remdays_{target_id}_30"))
        
        if (has_permission(admin_id, 'add_days') or has_permission(admin_id, 'remove_days') or admin_id == ADMIN_ID):
            kb.add(types.InlineKeyboardButton("🗑️ Удалить подписку", callback_data=f"usr_remsub_{target_id}"))
        
        if has_permission(admin_id, 'manage_users') or admin_id == ADMIN_ID:
            kb.add(types.InlineKeyboardButton("🔄 Сбросить ссылку", callback_data=f"admin_reset_link_{target_id}"))
        
        if (has_permission(admin_id, 'block_user') or admin_id == ADMIN_ID):
            if blk == 1:
                kb.add(types.InlineKeyboardButton("🔓 Разблокировать", callback_data=f"usr_unblock_{target_id}"))
            else:
                kb.add(types.InlineKeyboardButton("🔒 Заблокировать", callback_data=f"usr_block_{target_id}"))
        
        kb.row(
            types.InlineKeyboardButton("🔙 Назад к списку", callback_data="back_to_list"),
            types.InlineKeyboardButton("❌ Закрыть", callback_data="close_manage")
        )

        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            parse_mode="Markdown",
            reply_markup=kb
        )
    except Exception as e:
        print(f"[refresh_card] Ошибка: {e}")
        traceback.print_exc()
        bot.answer_callback_query(call.id, f"❌ Ошибка: {e}")

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_reset_link_"))
def callback_admin_reset_link(call):
    admin_id = call.from_user.id
    if not is_admin(admin_id):
        bot.answer_callback_query(call.id, "⛔️ Нет прав")
        return
        
    target_id = int(call.data.split('_')[3])
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        new_token = generate_subscription_token()
        cur.execute("UPDATE users SET token = %s WHERE user_id = %s", (new_token, target_id))
        conn.commit()
        clear_user_cache(target_id)
        
        log_admin_action(admin_id, "Сбросил ссылку подписки (токен)", target_id=target_id)
        bot.answer_callback_query(call.id, "🔄 Ссылка клиента успешно сброшена!", show_alert=True)
        
        # Уведомляем пользователя о сбросе
        try:
            bot.send_message(
                target_id, 
                "🔄 <b>Внимание!</b>\n\n"
                "Администратор перевыпустил ваш персональный токен подписки.\n"
                "Ваша старая ссылка заблокирована. Пожалуйста, зайдите в раздел 📡 <b>Моя подписка</b> и скопируйте новую ссылку для импорта в клиент.",
                parse_mode="HTML"
            )
        except:
            pass
            
    except Exception as e:
        print(f"[admin_reset_link] Ошибка: {e}")
        bot.answer_callback_query(call.id, "❌ Не удалось сбросить ссылку")
    finally:
        return_db_connection(conn)
        
    # Обновляем карточку пользователя для администратора
    _refresh_user_card(call, target_id, admin_id)

@app.route('/sub/<token>')
def serve_subscription(token):
    # Получаем реальный IP-адрес клиента на платформе Render
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    ua = request.headers.get('User-Agent', '').lower()
    referer = request.headers.get('Referer', '').lower()
    origin = request.headers.get('Origin', '').lower()
    
    # Выводим информацию в логи Render для мониторинга
    print(f"[sub_request] IP: {client_ip} | UA: {ua} | Referer: {referer} | Origin: {origin}")

    # 1. Блокировка по прямым признакам в заголовках браузера
    block_keywords = ['happy-decoder', 'unhapp', 'happwn', 'decoder', 'decrypt', 'all_subs', 'github']
    if any(kw in referer for kw in block_keywords) or any(kw in origin for kw in block_keywords):
        return "Access Denied: Web Decoder Blocked", 403

    # 2. Блокировка стандартных библиотек запросов
    blocked_agents = [
        'python-requests', 'node-fetch', 'axios', 'got', 'aiohttp', 'urllib',
        'go-http-client', 'curl', 'wget', 'postman', 'scrapy', 'libcurl',
        'httpclient', 'headless', 'playwright', 'puppeteer'
    ]
    if any(agent in ua for agent in blocked_agents):
        return "Access Denied: Scraper library blocked", 403

    # 3. Активная блокировка серверов и хостингов (Reverse DNS)
    try:
        socket.setdefaulttimeout(1.0)
        host_info = socket.gethostbyaddr(client_ip)
        hostname = host_info[0].lower() if host_info else ""
        
        hosting_keywords = [
            'hetzner', 'ovh', 'digitalocean', 'linode', 'amazon', 'aws', 'google', 
            'hosting', 'vps', 'server', 'cloud', 'contabo', 'scaleway', 'leaseweb', 
            'm2.ae', 'web-hosting', 'datacenter', 'dedicated'
        ]
        if any(kw in hostname for kw in hosting_keywords):
            print(f"[Block] Запрос заблокирован. IP {client_ip} принадлежит хостингу ({hostname})")
            return "Access Denied: Datacenter IP Blocked", 403
    except Exception:
        pass

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Считываем user_id, дату окончания подписки, статус блокировки/заморозки и статус индивидуального шифрования
        cur.execute("""
            SELECT user_id, subscription_end, is_blocked, is_frozen, COALESCE(encryption_enabled, 1) 
            FROM users WHERE token = %s
        """, (token,))
        user = cur.fetchone()
        if not user:
            return "Invalid token", 404
        
        # =========================================================
        # НОВАЯ ЛОГИКА ШИФРОВАНИЯ
        # =========================================================
        user_id, sub_end, is_blocked, is_frozen, user_crypt = user
        current_time = int(time.time())
        
        if is_blocked == 1 or is_frozen == 1 or sub_end < current_time:
            return "Subscription expired or blocked", 403
            
        raw_keys = get_subscription_keys_from_db()
        
        # Получаем глобальную настройку шифрования
        global_crypt = get_setting('global_encryption', '1') == '1'
        
        # Шифруем, если включено глобально И не отключено лично у пользователя (/crypt_off)
        use_encryption = global_crypt and (user_crypt == 1)
        
        if use_encryption:
            encrypted_lines = []
            for link in raw_keys:
                encrypted = parse_and_encrypt_vless(link, sub_end)
                if encrypted:
                    encrypted_lines.append(encrypted)
                else:
                    encrypted_lines.append(link) # Защита от потери ключа при ошибке
            final_text = "\n".join(encrypted_lines)
        else:
            final_text = "\n".join(raw_keys)
            
        # Кодируем итоговый результат в Base64 для передачи клиенту
        base64_response = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
        # =========================================================

        return base64_response, 200, {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': 'attachment; filename="subscription.txt"',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
        }
    except Exception as e:
        print(f"Ошибка в /sub/{token}: {e}")
        return "Internal Error", 500
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

@bot.callback_query_handler(func=lambda call: call.data.startswith('user_') and len(call.data.split('_')) == 2)
def callback_user_detail(call):
    user_id = call.from_user.id
    if not is_admin(user_id) and user_id != ADMIN_ID:
        bot.answer_callback_query(call.id, "❌ Нет доступа.")
        return
    
    try:
        target_id = int(call.data.split('_')[1])
    except ValueError:
        bot.answer_callback_query(call.id, "❌ Ошибка ID")
        return
    
    if not has_permission(user_id, 'manage_users') and user_id != ADMIN_ID:
        bot.answer_callback_query(call.id, "⛔️ У вас нет прав на управление пользователями.")
        return
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT user_id FROM users WHERE user_id = %s", (target_id,))
            exists = cur.fetchone()
        finally:
            try:
                cur.close()
            except:
                pass
            return_db_connection(conn)
        
        if not exists:
            bot.answer_callback_query(call.id, "❌ Пользователь не найден")
            return
            
        _refresh_user_card(call, target_id, user_id)
        
    except Exception as e:
        print(f"[callback_user_detail] Ошибка: {e}")
        bot.answer_callback_query(call.id, "❌ Ошибка")

def main_menu():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True)
    kb.row(
        types.KeyboardButton("👤 Личный кабинет"),
        types.KeyboardButton("📡 Моя подписка")
    )
    kb.row(
        types.KeyboardButton("👥 Рефералы"),
        types.KeyboardButton("🏆 Топ рефералов")
    )
    kb.row(
        types.KeyboardButton("ℹ️ Стаж бота"),
        types.KeyboardButton("📋 Правила")
    )
    kb.row(
        types.KeyboardButton("❓ Поддержка")
    )
    return kb

def subscribe_button():
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("📢 ПОДПИСАТЬСЯ", url=CHANNEL_LINK))
    kb.add(types.InlineKeyboardButton("✅ Я подписался", callback_data="check_sub"))
    return kb

def blocked_message():
    return f"🚫 Вы заблокированы администратором. Обратитесь в поддержку: {SUPPORT}"

def _format_duration(seconds):
    seconds = max(0, int(seconds))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts = []
    if days:
        parts.append(f"{days} дн")
    if hours or days:
        parts.append(f"{hours} ч")
    parts.append(f"{minutes} мин")
    return ' '.join(parts)

def get_bot_stats():
    ensure_bot_start_time()
    start_time = int(get_setting('bot_start_time', str(int(time.time()))))
    uptime_seconds = int(time.time()) - start_time
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)
    
    return {
        'uptime_text': _format_duration(uptime_seconds),
        'total_users': total_users,
        'current_keys': len(get_subscription_keys_from_db()), # <-- Изменено: теперь статистика берет актуальное число ключей из новой таблицы
    }

CAPTCHA_TIMEOUT = 300
SUBSCRIBE_MONITOR = {'timestamps': [], 'blocked_until': 0}
SUBSCRIBE_LIMIT = 100
SUBSCRIBE_BAN_TIME = 3600

def check_subscribe_rate():
    with _subscribe_monitor_lock:
        current_time = int(time.time())
        SUBSCRIBE_MONITOR['timestamps'] = [t for t in SUBSCRIBE_MONITOR['timestamps'] if current_time - t < 60]
        count = len(SUBSCRIBE_MONITOR['timestamps'])
        if current_time < SUBSCRIBE_MONITOR['blocked_until']:
            remaining = SUBSCRIBE_MONITOR['blocked_until'] - current_time
            return False, f"⏳ Подписки заблокированы. Осталось {remaining//60} мин."
        if count > SUBSCRIBE_LIMIT:
            SUBSCRIBE_MONITOR['blocked_until'] = current_time + SUBSCRIBE_BAN_TIME
            return False, "⚠️ Слишком много подписок. Попробуйте через час."
        return True, "OK"

def add_subscribe_record(user_id):
    with _subscribe_monitor_lock:
        SUBSCRIBE_MONITOR['timestamps'].append(int(time.time()))

def process_referral(referrer_id, referred_id):
    if referrer_id == referred_id:
        return False, "Нельзя пригласить самого себя"
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE user_id = %s FOR UPDATE", (referrer_id,))
        referrer_exists = cur.fetchone()
        if not referrer_exists:
            return False, "Реферер не найден"
        
        cur.execute("SELECT user_id, is_blocked FROM users WHERE user_id = %s FOR UPDATE", (referred_id,))
        referred = cur.fetchone()
        if not referred:
            return False, "Реферал не зарегистрирован в боте"
        if referred[1] == 1:
            return False, "Реферал заблокирован"
        
        referrer_subscribed = is_subscribed(referrer_id)
        referred_subscribed = is_subscribed(referred_id)
        
        if not referred_subscribed:
            return False, "Реферал не подписан на канал"
        
        today_start = int(time.time()) - 24 * 60 * 60
        cur.execute(
            "SELECT COUNT(*) FROM referrals WHERE referrer_id = %s AND reward_date > %s",
            (referrer_id, today_start)
        )
        count = cur.fetchone()[0]
        if count >= 10:
            return False, "Лимит рефералов (10 в день) превышен"
        
        current_time = int(time.time())
        try:
            cur.execute("""
                INSERT INTO referrals (referrer_id, referred_id, reward_date, rewarded, referrer_subscribed, referred_subscribed) 
                VALUES (%s, %s, %s, 0, %s, %s)
            """, (referrer_id, referred_id, current_time, 1 if referrer_subscribed else 0, 1))
            conn.commit()
        except Exception as e:
            conn.rollback()
            if 'unique' in str(e).lower():
                return False, "Этот пользователь уже был приглашен"
            raise
        
        if referrer_subscribed:
            cur.execute("SELECT subscription_end FROM users WHERE user_id = %s FOR UPDATE", (referrer_id,))
            ref_result = cur.fetchone()
            if ref_result:
                new_end = ref_result[0] + 3 * 24 * 60 * 60
                cur.execute("UPDATE users SET subscription_end = %s, notified_3days = 0 WHERE user_id = %s", 
                           (new_end, referrer_id))
                cur.execute(
                    "UPDATE referrals SET rewarded = 1 WHERE referrer_id = %s AND referred_id = %s",
                    (referrer_id, referred_id)
                )
                conn.commit()
                try:
                    bot.send_message(referrer_id, "🎉 Вам начислено +3 дня за нового реферала!")
                except:
                    pass
                return True, "Реферал добавлен, начислено +3 дня"
        
        conn.commit()
        return True, "Реферал сохранен"
    except Exception as e:
        print(f"[process_referral] Ошибка: {e}")
        try:
            conn.rollback()
        except:
            pass
        return False, f"Ошибка: {e}"
    finally:
        try:
            if cur:
                cur.close()
        except:
            pass
        if conn:
            return_db_connection(conn)

_LEFT_STATUSES = ('left', 'kicked')

if hasattr(bot, 'chat_member_handler'):
    @bot.chat_member_handler()
    def handle_channel_membership_change(update):
        try:
            if update.chat.id != CHANNEL_ID:
                return
            old_status = update.old_chat_member.status
            new_status = update.new_chat_member.status
            if old_status not in _LEFT_STATUSES and new_status in _LEFT_STATUSES:
                _revoke_referral_reward(update.new_chat_member.user.id)
        except Exception as e:
            print(f"[handle_channel_membership_change] Ошибка: {e}")
else:
    print("[init] ⚠️ chat_member_handler недоступен")


def _revoke_referral_reward(referred_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT referrer_id FROM referrals WHERE referred_id = %s AND rewarded = 1",
            (referred_id,)
        )
        row = cur.fetchone()
        if not row:
            return
        referrer_id = row[0]

        cur.execute("SELECT subscription_end FROM users WHERE user_id = %s FOR UPDATE", (referrer_id,))
        ref_result = cur.fetchone()
        if not ref_result:
            return

        new_end = max(0, ref_result[0] - 3 * 24 * 60 * 60)
        cur.execute("UPDATE users SET subscription_end = %s WHERE user_id = %s", (new_end, referrer_id))
        cur.execute(
            "UPDATE referrals SET rewarded = 0 WHERE referred_id = %s AND referrer_id = %s",
            (referred_id, referrer_id)
        )
        conn.commit()

        try:
            bot.send_message(referrer_id, "⚠️ Ваш реферал отписался от канала — с вас списано 3 дня подписки.")
        except:
            pass
        log_admin_action(referred_id, f"Реферал отписался, списано 3 дня у {referrer_id}", target_id=referrer_id)
    except Exception as e:
        print(f"[_revoke_referral_reward] Ошибка: {e}")
        try:
            conn.rollback()
        except:
            pass
    finally:
        try:
            cur.close()
        except:
            pass
        return_db_connection(conn)

def run_bot():
    while True:
        try:
            print("[bot] Запуск polling...")
            bot.infinity_polling(timeout=60, long_polling_timeout=60)
        except Exception as e:
            print(f"[bot] Ошибка polling: {e}")
            time.sleep(5)

if __name__ == '__main__':
    print("=== Инициализация системы WSVPN (SQLite Mode) ===")
    
    if not os.path.exists("wsvpn.db"):
        open("wsvpn.db", "w").close()
    
    init_db()
    load_maintenance_mode() # <-- ДОБАВИТЬ ЭТУ СТРОКУ (Синхронизирует режим тех. работ из БД в оперативку на старте)
    
    Thread(target=cleanup_sessions_scheduler, daemon=True).start()
    Thread(target=run_bot, daemon=True).start()
    
    print("📍 Админка: http://localhost:8080/admin")
    port = int(os.environ.get("PORT", 8080))
    serve(app, host='0.0.0.0', port=port, threads=8)
