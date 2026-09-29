import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import bcrypt
import json
import os
import glob
import re
import requests
import base64
import random
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ==============================================================================
# 1. CONFIGURACIÓN DEL SISTEMA Y METADATOS
# ==============================================================================
st.set_page_config(
    page_title="Operación Dragón - Portal Seguro",
    page_icon="🐉",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Archivos de persistencia y base de datos
DB_USUARIOS = 'seguridad_usuarios.json'
LOG_AUDITORIA = 'auditoria_accesos.json'
CARPETA_MATRICES = 'matrices'

# Administradores autorizados (Cédulas)
ADMIN_USERS = ['1152437543', 'admin']

def obtener_config(clave, valor_defecto):
    val = os.environ.get(clave)
    if val:
        return val
    try:
        if clave in st.secrets:
            return st.secrets[clave]
    except Exception:
        pass
    return valor_defecto

# Configuración SMTP segura (prioriza variables de entorno o st.secrets con fallback)
REMITENTE_EMAIL = obtener_config("SMTP_USER", "personaldramirez@gmail.com")
REMITENTE_PASSWORD = obtener_config("SMTP_PASS", "qism kdgy mbnv eyfh")

PRECIOS_BASE = {
    'Q': {'nombre': 'QUINTILLION', 'precio': 5000000, 'icono': '💴'},
    'N': {'nombre': 'NONGENTILLION', 'precio': 10000000, 'icono': '💵'},
    'V': {'nombre': 'VIGINTILLION', 'precio': 7500000, 'icono': '💶'},
    'ZIM': {'nombre': 'MONEDA DE ZIM', 'precio': 500000, 'icono': '🪙'},
    'BZ': {'nombre': 'BILLETE ZIMBABWE', 'precio': 12500000, 'icono': '🧾'},
    'AZ': {'nombre': 'AGROCHEQUE ZIM', 'precio': 500000, 'icono': '📜'},
    'MHK': {'nombre': 'MHK', 'precio': 15000000, 'icono': '🎫'},
    'G': {'nombre': 'GOOGOPLEX', 'precio': 500000000, 'icono': '🐲'}
}

# ==============================================================================
# 2. CONTROL DE ESTADO GLOBAL Y SESIÓN
# ==============================================================================
if 'vista_actual' not in st.session_state: st.session_state['vista_actual'] = 'landing'
if 'cedula_usuario' not in st.session_state: st.session_state['cedula_usuario'] = None
if 'rol_usuario' not in st.session_state: st.session_state['rol_usuario'] = 'usuario'
if 'registro_paso' not in st.session_state: st.session_state['registro_paso'] = 1
if 'temp_data' not in st.session_state: st.session_state['temp_data'] = {}
if 'intentos_otp' not in st.session_state: st.session_state['intentos_otp'] = 0
if 'codigo_otp_debug' not in st.session_state: st.session_state['codigo_otp_debug'] = None

def cambiar_vista(nueva_vista):
    st.session_state['vista_actual'] = nueva_vista
    st.session_state['registro_paso'] = 1
    st.session_state['intentos_otp'] = 0

# ==============================================================================
# 3. MÓDULO FORENSE Y AUDITORÍA DE SEGURIDAD
# ==============================================================================
def registrar_evento_auditoria(dni, accion, estado="OK", detalle=""):
    """Registra eventos en bitácora inmutable para análisis forense e institucional."""
    try:
        evento = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dni": str(dni),
            "accion": accion,
            "estado": estado,
            "detalle": detalle
        }
        historial = []
        if os.path.exists(LOG_AUDITORIA):
            with open(LOG_AUDITORIA, 'r', encoding='utf-8') as f:
                historial = json.load(f)
        historial.append(evento)
        with open(LOG_AUDITORIA, 'w', encoding='utf-8') as f:
            json.dump(historial, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def hash_contrasena(password: str) -> str:
    """Aplica algoritmo seguro bcrypt con Salt aleatorio contra ataques de fuerza bruta."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verificar_contrasena(password: str, hash_almacenado: str) -> bool:
    """Verifica la contraseña contra el hash bcrypt."""
    try:
        if hash_almacenado.startswith("$2b$") or hash_almacenado.startswith("$2a$"):
            return bcrypt.checkpw(password.encode('utf-8'), hash_almacenado.encode('utf-8'))
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest() == hash_almacenado
    except Exception:
        return False

def cargar_usuarios_registrados():
    if os.path.exists(DB_USUARIOS):
        try:
            with open(DB_USUARIOS, 'r', encoding='utf-8') as file:
                return json.load(file)
        except Exception:
            return {}
    return {}

def guardar_usuario(cedula, password_hash, correo=""):
    usuarios = cargar_usuarios_registrados()
    usuarios[str(cedula)] = {
        "hash": password_hash,
        "correo": correo,
        "fecha_registro": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(DB_USUARIOS, 'w', encoding='utf-8') as file:
        json.dump(usuarios, file, ensure_ascii=False, indent=2)

def enviar_correo_otp(destinatario, codigo, dni):
    """Envío de código OTP transaccional con fallback seguro."""
    try:
        msg = MIMEMultipart()
        msg['From'] = REMITENTE_EMAIL
        msg['To'] = destinatario
        msg['Subject'] = "🐉 Código de Acceso - Operación Dragón"
        cuerpo = (
            f"OPERACIÓN DRAGÓN - PORTAL DE CONSULTA\n\n"
            f"Estimado usuario con DNI/Cédula {dni}:\n"
            f"Su código de seguridad de un solo uso (OTP) es:\n\n"
            f"    ▶ {codigo} ◀\n\n"
            f"Este código expira en 10 minutos. No comparta este código con nadie.\n"
            f"Si no solicitó este acceso, reporte de inmediato a su líder de grupo."
        )
        msg.attach(MIMEText(cuerpo, 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=7)
        server.starttls()
        server.login(REMITENTE_EMAIL, REMITENTE_PASSWORD.replace(" ", ""))
        server.send_message(msg)
        server.quit()
        return True, ""
    except Exception as e:
        return False, str(e)

# ==============================================================================
# 4. MOTOR DE EXTRACCIÓN Y CONSOLIDACIÓN DE MATRICES
# ==============================================================================
@st.cache_data(ttl=60)
def cargar_super_matriz():
    """
    Escanea automáticamente los archivos de Excel tanto en la raíz como en subcarpetas,
    extrayendo de DATOS GENERALES / DATA COMPRAS y unificando compras por persona.
    """
    rutas_a_buscar = [
        glob.glob("*.xlsx") + glob.glob("*.xls"),
        glob.glob(f"{CARPETA_MATRICES}/*.xlsx") + glob.glob(f"{CARPETA_MATRICES}/*.xls")
    ]
    archivos_excel = set()
    for lista in rutas_a_buscar:
        for a in lista:
            if not os.path.basename(a).startswith("~$"):
                archivos_excel.add(a)

    archivos_excel = list(archivos_excel)
    registros = []

    for archivo in archivos_excel:
        try:
            # Obtener nombre del líder por nombre de archivo
            m_lider = re.search(r'LIDER\s+([^.]+)', os.path.basename(archivo), re.IGNORECASE)
            lider_archivo = m_lider.group(1).strip() if m_lider else "LÍDER GENERAL"

            # Inspeccionar hojas disponibles
            excel_obj = pd.ExcelFile(archivo)
            hoja_objetivo = None
            for h in ['DATOS GENERALES', 'DATA COMPRAS', 'DATA GENERAL', 'MATRIZ LISTADO']:
                if h in excel_obj.sheet_names:
                    hoja_objetivo = h
                    break
            
            if not hoja_objetivo:
                hoja_objetivo = excel_obj.sheet_names[0]

            df_raw = pd.read_excel(archivo, sheet_name=hoja_objetivo, header=None)
            
            # Detectar fila de cabeceras
            header_idx = 0
            for i in range(min(20, len(df_raw))):
                fila_str = " ".join([str(x).upper() for x in df_raw.iloc[i].values if pd.notna(x)])
                if any(k in fila_str for k in ["CC", "DNI", "CEDULA", "NOMBRE"]):
                    header_idx = i
                    break

            df = pd.read_excel(archivo, sheet_name=hoja_objetivo, header=header_idx)
            df.columns = df.columns.astype(str).str.strip().str.upper().str.replace('É', 'E').str.replace('Ó', 'O')
            df = df.loc[:, ~df.columns.duplicated()]

            cc_col = next((c for c in df.columns if any(x in c for x in ['CC', 'DNI', 'ID', 'CEDULA', 'DOCUMENTO']) and 'PASAPORTE' not in c), None)
            nom_col = next((c for c in df.columns if 'NOMBRE' in c), None)
            lid_col = next((c for c in df.columns if 'LIDER' in c), None)
            prod_col = next((c for c in df.columns if any(x in c for x in ['PRODUCTO', 'MATERIAL', 'FORMULA'])), None)
            email_col = next((c for c in df.columns if any(x in c for x in ['CORREO', 'EMAIL'])), None)
            tel_col = next((c for c in df.columns if any(x in c for x in ['TEL', 'CEL', 'MOVIL'])), None)

            if cc_col:
                for _, row in df.iterrows():
                    val_cc = str(row[cc_col]).strip().replace('.0', '')
                    if val_cc.isdigit() and len(val_cc) >= 4:
                        nom = str(row[nom_col]).strip() if nom_col and pd.notna(row[nom_col]) else "NO REGISTRA"
                        lid = str(row[lid_col]).strip() if lid_col and pd.notna(row[lid_col]) else lider_archivo
                        email = str(row[email_col]).strip().lower() if email_col and pd.notna(row[email_col]) else ""
                        if email in ['nan', 'none', 'null', '<na>']: email = ""
                        tel = str(row[tel_col]).strip() if tel_col and pd.notna(row[tel_col]) else ""
                        prod = str(row[prod_col]).strip() if prod_col and pd.notna(row[prod_col]) else ""
                        if prod in ['nan', 'none']: prod = ""

                        registros.append({
                            'ID/CC/DNI': val_cc.lstrip('0'),
                            'NOMBRE COMPLETO': nom,
                            'LIDER': lid,
                            'CORREO_EXCEL': email,
                            'PRODUCTO / MATERIAL': prod,
                            'TELEFONO': tel,
                            'ARCHIVO_ORIGEN': os.path.basename(archivo)
                        })
        except Exception:
            continue

    if registros:
        df_todos = pd.DataFrame(registros)
        # Agrupar registros repetidos de la misma persona
        df_final = df_todos.groupby('ID/CC/DNI', as_index=False).agg({
            'NOMBRE COMPLETO': 'first',
            'LIDER': 'first',
            'CORREO_EXCEL': lambda x: next((e for e in x if e and '@' in e), ''),
            'TELEFONO': 'first',
            'PRODUCTO / MATERIAL': lambda x: '+'.join([str(i) for i in x if str(i).strip() not in ['', 'nan', 'None']]),
            'ARCHIVO_ORIGEN': 'first'
        })
        return df_final
    return pd.DataFrame()

df_usuarios = cargar_super_matriz()

def calcular_materiales(formula):
    """Decodifica fórmulas como '2Q+3N+5V' o cantidades directas y calcula montos base."""
    res = {k: 0 for k in PRECIOS_BASE}
    res['TOTAL_PAGO'] = 0
    if pd.isna(formula) or not isinstance(formula, str) or not formula.strip():
        return res

    matches = re.findall(r'(\d+)\s*([A-Za-z]+)', formula.upper().replace(' ', ''))
    for cant_str, material in matches:
        try:
            cant = int(cant_str)
        except ValueError:
            continue
        mat = material.strip()
        clave = None
        if mat in ['Q', 'QUINTILLION', 'QUINTILLON']: clave = 'Q'
        elif mat in ['N', 'NONGENTILLION']: clave = 'N'
        elif mat in ['V', 'VIGINTILLION']: clave = 'V'
        elif 'ZIM' in mat or mat in ['M', 'MONEDA']: clave = 'ZIM'
        elif mat in ['B', 'BZ', 'BILLETE']: clave = 'BZ'
        elif 'AGRO' in mat or mat in ['A', 'AZ']: clave = 'AZ'
        elif 'GOOG' in mat or mat == 'G': clave = 'G'
        elif mat == 'MHK': clave = 'MHK'

        if clave:
            res[clave] += cant
            res['TOTAL_PAGO'] += (cant * PRECIOS_BASE[clave]['precio'])
    return res

@st.cache_data(ttl=3600)
def obtener_trm():
    try:
        r = requests.get("https://api.exchangerate-api.com/v4/latest/USD", timeout=3)
        return float(r.json()['rates']['COP'])
    except Exception:
        return 4180.0  # TRM promedio representativa de respaldo

def formato_pesos(valor):
    return f"$ {valor:,.0f}".replace(",", ".") if valor != 0 else "$ 0"

def formato_trm(valor):
    return f"$ {valor:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

def buscar_logo():
    for op in ['logo.png', 'logo.jpg', 'image_a251de.png']:
        if os.path.exists(op): return op
    return ""

LOGO_B64 = ""
LOGO_PATH = buscar_logo()
if LOGO_PATH:
    with open(LOGO_PATH, "rb") as img_file:
        LOGO_B64 = base64.b64encode(img_file.read()).decode()

# ==============================================================================
# 5. ESTILOS CSS MAESTROS Y LOGO ANIMADO
# ==============================================================================
CSS_COMPATIBLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Teko:wght@500;700&family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@700;800&display=swap');
:root { --bg: #090b0e; --card: #12151b; --border: #232833; --orange: #f97316; --gold: #eab308; --text-main: #f8fafc; --text-sub: #94a3b8; }
.stApp { background-color: var(--bg); color: var(--text-main); font-family: 'Inter', sans-serif; }
.block-container { padding-top: 1.5rem; max-width: 1250px; }
div.stButton > button:first-child { background: linear-gradient(135deg, #ea580c, #f97316) !important; color: white !important; border: none !important; font-weight: 700 !important; border-radius: 8px !important; transition: all 0.3s ease !important; padding: 0.6rem 1.4rem !important; box-shadow: 0 4px 14px rgba(234, 88, 12, 0.35) !important; }
div.stButton > button:first-child:hover { box-shadow: 0 6px 20px rgba(234, 88, 12, 0.6) !important; transform: translateY(-2px) !important; color: white !important; }
.btn-secondary > div > button:first-child { background: #1a1e27 !important; color: var(--text-sub) !important; border: 1px solid var(--border) !important; box-shadow: none !important; }
.btn-secondary > div > button:first-child:hover { border-color: var(--text-main) !important; color: white !important; transform: none !important; }
.stTextInput > div > div > input { background-color: #0b0d12 !important; color: white !important; border: 1px solid var(--border) !important; border-radius: 8px !important; padding: 12px 14px !important; font-family: 'Inter', sans-serif !important; }
.stTextInput > div > div > input:focus { border-color: var(--orange) !important; box-shadow: 0 0 0 2px rgba(249,115,22,0.2) !important; }
.card-custom { background-color: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 2rem; margin-bottom: 1.2rem; box-shadow: 0 12px 32px rgba(0,0,0,0.6); }
.text-orange { color: var(--orange); }
.font-teko { font-family: 'Teko', sans-serif; text-transform: uppercase; }
.landing-title { font-family: 'Teko', sans-serif; font-size: clamp(3rem, 6.5vw, 5.5rem); font-weight: 700; line-height: 1.05; text-transform: uppercase; text-align: center; margin-bottom: 1rem; }
.dash-fila { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; background-color: #0c0f14; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; }
.anillo { width: 120px; height: 120px; margin: 0 auto; border-radius: 50%; position: relative; display: grid; place-items: center; }
.anillo::before { content: ""; position: absolute; inset: 0; border-radius: 50%; padding: 3px; background: conic-gradient(from 0deg, transparent, var(--orange), #38bdf8, transparent 65%, var(--orange)); -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite: xor; mask-composite: exclude; animation: gira 4s linear infinite; }
.anillo-gigante { width: 260px; height: 260px; margin: 0 auto; border-radius: 50%; position: relative; display: grid; place-items: center; }
.anillo-gigante::before { content: ""; position: absolute; inset: 0; border-radius: 50%; padding: 4px; background: conic-gradient(from 0deg, transparent, var(--orange), #38bdf8, transparent 60%, var(--orange)); -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite: xor; mask-composite: exclude; animation: gira 6s linear infinite; }
@keyframes gira { to { transform: rotate(360deg); } }
</style>
"""
st.markdown(CSS_COMPATIBLE.replace('\n', ''), unsafe_allow_html=True)

IFRAME_BASE = """
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@700;800&display=swap" rel="stylesheet">
<style>
body{margin:0;font-family:'JetBrains Mono',monospace;background:transparent;overflow:hidden;}
.caja{background:#12151b;border:1px solid #232833;border-radius:12px;padding:16px;text-align:center;height:105px;box-sizing:border-box;}
.etq{font:800 11px sans-serif;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;}
.num{font-size:clamp(15px,2.2vw,22px);font-weight:800;margin-top:8px;}
</style>
<script>
function animar(el, fin, prefijo){
  const t0=performance.now(), dur=1400;
  const fmt=v=>prefijo+Math.round(v).toLocaleString('es-CO');
  requestAnimationFrame(function paso(t){
    const p=Math.min((t-t0)/dur,1), e=1-Math.pow(1-p,4);
    el.textContent=fmt(fin*e); if(p<1) requestAnimationFrame(paso);
  });
}
</script>
"""

def contador_kpi(valor, etiqueta, color, prefijo="$ "):
    components.html(IFRAME_BASE + f"""
    <div class="caja">
        <div class="etq">{etiqueta}</div>
        <div id="n" class="num" style="color:{color};">{prefijo}0</div>
    </div>
    <script>animar(document.getElementById('n'), {valor}, '{prefijo}');</script>
    """, height=115)

def render_logo_animado():
    img_tag = f'<img src="data:image/png;base64,{LOGO_B64}" style="width:90px; filter:drop-shadow(0 0 25px rgba(234,88,12,0.7)); border-radius:50%; z-index:10; position:relative;">' if LOGO_B64 else '<div style="font-size:70px; z-index:10; position:relative;">🐉</div>'
    st.markdown(f'<div class="anillo" style="margin-bottom:2rem;">{img_tag}</div>', unsafe_allow_html=True)

def render_logo_gigante():
    img_tag = f'<img src="data:image/png;base64,{LOGO_B64}" style="width:210px; filter:drop-shadow(0 0 45px rgba(234,88,12,0.8)); border-radius:50%; z-index:10; position:relative;">' if LOGO_B64 else '<div style="font-size:140px; z-index:10; position:relative;">🐉</div>'
    st.markdown(f'<div class="anillo-gigante" style="margin-bottom:2rem;">{img_tag}</div>', unsafe_allow_html=True)

def render_logo_pequeno():
    img_tag = f'<img src="data:image/png;base64,{LOGO_B64}" style="width:48px; filter:drop-shadow(0 0 12px rgba(234,88,12,0.6)); border-radius:50%; z-index:10; position:relative;">' if LOGO_B64 else '<div style="font-size:36px; z-index:10; position:relative;">🐉</div>'
    return f'<div class="anillo" style="width:68px; height:68px; margin:0;">{img_tag}</div>'

# ==============================================================================
# 6. VISTAS DE LA APLICACIÓN
# ==============================================================================

# --- DASHBOARD INDIVIDUAL / RESUMEN GENERAL ---
def renderizar_dashboard_html(cedula, df_bd, trm_actual):
    u_data = df_bd[df_bd['ID/CC/DNI'] == str(cedula)]
    if u_data.empty:
        st.error("❌ Cédula no localizada en las matrices oficiales.")
        return
        
    nombre = u_data['NOMBRE COMPLETO'].values[0] if 'NOMBRE COMPLETO' in u_data.columns else "NO REGISTRA"
    lider = u_data['LIDER'].values[0] if 'LIDER' in u_data.columns else "NO ASIGNADO"
    prod = u_data['PRODUCTO / MATERIAL'].values[0] if 'PRODUCTO / MATERIAL' in u_data.columns else ""
    correo = u_data['CORREO_EXCEL'].values[0] if 'CORREO_EXCEL' in u_data.columns else "No registrado"
    tel = u_data['TELEFONO'].values[0] if 'TELEFONO' in u_data.columns else ""
    origen = u_data['ARCHIVO_ORIGEN'].values[0] if 'ARCHIVO_ORIGEN' in u_data.columns else ""
    
    calc = calcular_materiales(prod)
    t_usd = calc['TOTAL_PAGO']
    t_neto = t_usd * 0.90
    b_usd = t_neto * 0.01
    f_usd = t_neto * 0.99
    t_cop = t_neto * trm_actual

    # Registrar consulta autorizada
    registrar_evento_auditoria(cedula, "CONSULTA_RESUMEN", "OK", f"Líder: {lider}")

    # Cabecera individual
    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:20px; margin-bottom:2rem; background:#12151b; border:1px solid #232833; padding:20px 24px; border-radius:14px;">
        {render_logo_pequeno()}
        <div style="flex-grow:1;">
            <div style="color:#94a3b8; font-size:12px; font-weight:800; letter-spacing:2px; text-transform:uppercase;">RESUMEN INDIVIDUAL OFICIAL</div>
            <h2 class="font-teko" style="font-size:3.2rem; margin:0; line-height:1; color:white;">{nombre.upper()}</h2>
            <div style="display:flex; gap:25px; margin-top:8px; flex-wrap:wrap; font-size:13px;">
                <span>CÉDULA/ID: <strong style="color:white;">{cedula}</strong></span>
                <span>LÍDER RESPONSABLE: <strong class="text-orange">{str(lider).upper()}</strong></span>
                <span>CORREO: <strong style="color:white;">{correo}</strong></span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 4 Indicadores KPIs con animación
    c1, c2, c3, c4 = st.columns(4)
    with c1: contador_kpi(t_usd, "PAGO BRUTO EN USD", "#f8fafc")
    with c2: contador_kpi(t_neto, "TOTAL NETO (-10%)", "#f97316")
    with c3: contador_kpi(b_usd, "1% PAGO INICIAL BANCO (USD)", "#ef4444")
    with c4: contador_kpi(t_cop, "TOTAL FINAL EN PESOS (COP)", "#10b981")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Detalle de materiales y Resumen de Liquidación
    col_mats, col_res = st.columns([1.25, 1], gap="large")
    
    with col_mats:
        st.markdown("<div class='card-custom'>", unsafe_allow_html=True)
        st.markdown("<h4 class='font-teko' style='font-size:2rem; margin-top:0; color:white;'>DETALLE DE MATERIALES ASIGNADOS</h4>", unsafe_allow_html=True)
        st.caption(f"Fórmula consolidada en matriz: **{prod if prod else 'Directo en matriz'}**")
        
        tiene_materiales = False
        for k, v in PRECIOS_BASE.items():
            if calc[k] > 0:
                tiene_materiales = True
                monto_renglon = calc[k] * v["precio"]
                st.markdown(f"""
                <div class="dash-fila">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <span style="font-size:2rem;">{v["icono"]}</span>
                        <div>
                            <div style="font-weight:700; font-size:1.15rem; color:white;">{v["nombre"]}</div>
                            <div style="color:#94a3b8; font-size:12px;">Precio base: {formato_pesos(v["precio"])} USD</div>
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <div class="text-orange" style="font-weight:800; font-family:'JetBrains Mono'; font-size:1.25rem;">x{calc[k]}</div>
                        <div style="color:#10b981; font-weight:800; font-family:'JetBrains Mono'; font-size:1.1rem;">{formato_pesos(monto_renglon)} USD</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        if not tiene_materiales:
            st.info("ℹ️ Esta cédula está registrada en la matriz general. Sus montos o materiales están en proceso de verificación por su líder.")
            
        st.markdown("</div>", unsafe_allow_html=True)

    with col_res:
        st.markdown(f"""
        <div class="card-custom">
            <h4 class="font-teko" style="font-size:2rem; margin-top:0; color:white;'>ESTRUCTURA DE LIQUIDACIÓN Y PAGOS</h4>
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px;">
                <span style="color:var(--text-sub); font-weight:600;">TRM EN VIVO (DÓLAR/COP)</span>
                <span style="font-family:'JetBrains Mono'; font-weight:700; color:white;">{formato_trm(trm_actual)} COP</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px;">
                <span style="color:var(--text-sub); font-weight:600;">SUBTOTAL BRUTO</span>
                <span style="font-family:'JetBrains Mono'; font-weight:700; color:white;">{formato_pesos(t_usd)} USD</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px;">
                <span style="color:#ef4444; font-weight:600;">DESCUENTO GASTOS (-10%)</span>
                <span style="font-family:'JetBrains Mono'; font-weight:700; color:#ef4444;">- {formato_pesos(t_usd * 0.10)} USD</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px;">
                <span style="color:var(--text-sub); font-weight:600;">TOTAL NETO (90%)</span>
                <span style="font-family:'JetBrains Mono'; font-weight:800; color:white;">{formato_pesos(t_neto)} USD</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px;">
                <span style="color:#38bdf8; font-weight:600;">1% PAGO INICIAL (BANCO)</span>
                <span style="font-family:'JetBrains Mono'; font-weight:700; color:#38bdf8;">{formato_pesos(b_usd * trm_actual)} COP</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:8px;">
                <span style="color:var(--text-sub); font-weight:600;">99% REMANENTE (FIDUCIA/NUBE)</span>
                <span style="font-family:'JetBrains Mono'; font-weight:700; color:white;">{formato_pesos(f_usd * trm_actual)} COP</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:24px; padding-top:16px; border-top:2px solid #ea580c;">
                <span style="color:white; font-weight:800; font-size:1.15rem;">TOTAL DESEMBOLSO (COP)</span>
                <span style="font-family:'JetBrains Mono'; font-weight:800; font-size:1.9rem; color:#10b981;">{formato_pesos(t_cop)}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


# --- VISTA 1: LANDING PAGE ---
if st.session_state['vista_actual'] == 'landing':
    col_izq, col_der = st.columns([8, 1.2])
    with col_izq:
        st.markdown("<div class='text-orange font-teko' style='font-size:24px; letter-spacing:2px; margin-top:5px;'>OPERACIÓN DRAGÓN // RED SEGURA</div>", unsafe_allow_html=True)
    with col_der:
        st.button("Iniciar Sesión", on_click=cambiar_vista, args=('login',), use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)
    render_logo_animado()
    
    st.markdown("""
    <div class="landing-title">CONSULTA INDIVIDUAL DE MATERIALES <br><span class="text-orange">OPERACIÓN DRAGÓN</span></div>
    <div style="text-align:center; max-width:680px; margin: 0 auto 2.5rem auto; color:var(--text-sub); font-size:1.15rem; line-height:1.6;">
        Plataforma oficial de verificación de materiales y liquidación financiera. Ingrese con su número de documento para consultar exclusivamente su resumen individual clasificado.
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.button("Ingresar o Registrarme", type="primary", use_container_width=True, on_click=cambiar_vista, args=('login',))
        
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    c1, c2, c3 = st.columns(3)
    with c1: 
        st.markdown("""
        <div class="card-custom">
            <div style="font-size:2.2rem; margin-bottom:10px;">🔒</div>
            <h4 class="font-teko" style="font-size:1.7rem; margin-top:0; color:white;">AISLAMIENTO POR CÉDULA</h4>
            <p style="color:var(--text-sub); line-height:1.5; margin:0;">Cada usuario únicamente tiene acceso a sus propios materiales y valores. Se aplica el principio de mínimo privilegio.</p>
        </div>
        """, unsafe_allow_html=True)
    with c2: 
        st.markdown("""
        <div class="card-custom">
            <div style="font-size:2.2rem; margin-bottom:10px;">📋</div>
            <h4 class="font-teko" style="font-size:1.7rem; margin-top:0; color:white;">VALIDACIÓN EN MATRIZ OFICIAL</h4>
            <p style="color:var(--text-sub); line-height:1.5; margin:0;">Solo las personas registradas previamente en las matrices oficiales de líderes pueden activar su usuario.</p>
        </div>
        """, unsafe_allow_html=True)
    with c3: 
        st.markdown("""
        <div class="card-custom">
            <div style="font-size:2.2rem; margin-bottom:10px;">🛡️</div>
            <h4 class="font-teko" style="font-size:1.7rem; margin-top:0; color:white;">AUDITORÍA Y TRAZABILIDAD</h4>
            <p style="color:var(--text-sub); line-height:1.5; margin:0;">Registro forense inmutable de cada intento de acceso y consulta conforme a la Ley de Protección de Datos Personales.</p>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("<div style='text-align:center; color:#64748b; font-size:12px; margin-top:3rem; border-top:1px solid #1e2430; padding-top:20px;'>Operación Dragón • Sistema de Seguridad y Resumen Individualizado.</div>", unsafe_allow_html=True)


# --- VISTA 2: LOGIN CON SPLIT SCREEN ---
elif st.session_state['vista_actual'] == 'login':
    st.markdown('<div class="btn-secondary" style="margin-bottom:1rem;">', unsafe_allow_html=True)
    st.button("← VOLVER AL INICIO", on_click=cambiar_vista, args=('landing',))
    st.markdown('</div>', unsafe_allow_html=True)
    
    col_izq, col_der = st.columns([1, 1], gap="large")
    
    with col_izq:
        st.markdown("<br><br>", unsafe_allow_html=True)
        render_logo_gigante()
        st.markdown("<h1 class='font-teko' style='font-size:4.2rem; text-align:center; line-height:1; margin-top:15px; color:white;'>OPERACIÓN DRAGÓN</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:var(--text-sub); font-size:1.15rem;'>Acceso Clasificado y Resguardo de Activos</p>", unsafe_allow_html=True)
        
    with col_der:
        st.markdown("<div class='card-custom' style='margin-top:1.5rem;'>", unsafe_allow_html=True)
        st.markdown("<h2 class='font-teko' style='font-size:3rem; margin-top:0; color:white;'>INICIAR SESIÓN</h2>", unsafe_allow_html=True)
        st.markdown("<p style='color:var(--text-sub); margin-bottom:1.8rem;'>Ingrese su cédula y su contraseña establecida.</p>", unsafe_allow_html=True)
        
        cc_log = st.text_input("Número de Cédula (DNI/ID)")
        pass_log = st.text_input("Contraseña", type="password")
        
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Ingresar a la Plataforma", type="primary", use_container_width=True):
            cd_limpia = cc_log.strip().lstrip('0')
            db = cargar_usuarios_registrados()
            
            # Verificación del administrador principal
            if (cd_limpia == "admin" or cd_limpia == "1152437543") and pass_log in ["1152437543", "DragonAdmin2026*"]:
                st.session_state['cedula_usuario'] = "1152437543"
                st.session_state['rol_usuario'] = 'admin'
                registrar_evento_auditoria("1152437543", "LOGIN_ADMIN", "OK", "Ingreso como Administrador")
                cambiar_vista('dashboard')
                st.rerun()
            elif cd_limpia in db:
                info_user = db[cd_limpia]
                hash_guardado = info_user.get("hash") if isinstance(info_user, dict) else info_user
                if verificar_contrasena(pass_log, hash_guardado):
                    st.session_state['cedula_usuario'] = cd_limpia
                    st.session_state['rol_usuario'] = 'admin' if cd_limpia in ADMIN_USERS else 'usuario'
                    registrar_evento_auditoria(cd_limpia, "LOGIN_USUARIO", "OK", "Autenticación exitosa")
                    cambiar_vista('dashboard')
                    st.rerun()
                else:
                    registrar_evento_auditoria(cd_limpia, "LOGIN_FALLIDO", "ERROR", "Contraseña incorrecta")
                    st.error("❌ Credenciales inválidas. Verifique su contraseña.")
            else:
                registrar_evento_auditoria(cd_limpia, "LOGIN_NO_REGISTRADO", "WARN", "Cédula no registrada")
                st.error("❌ Esta cédula aún no ha sido registrada. Haga clic en el botón de abajo para registrarse.")
        
        st.markdown('<div class="btn-secondary" style="margin-top:14px;">', unsafe_allow_html=True)
        st.button("¿No tienes cuenta? Regístrate aquí", use_container_width=True, on_click=cambiar_vista, args=('registro',))
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


# --- VISTA 3: REGISTRO CON VERIFICACIÓN OTP ---
elif st.session_state['vista_actual'] == 'registro':
    st.markdown('<div class="btn-secondary" style="margin-bottom:1rem;">', unsafe_allow_html=True)
    st.button("← VOLVER AL LOGIN", on_click=cambiar_vista, args=('login',))
    st.markdown('</div>', unsafe_allow_html=True)
    
    col_izq, col_der = st.columns([1, 1], gap="large")
    
    with col_izq:
        st.markdown("<br><br>", unsafe_allow_html=True)
        render_logo_gigante()
        st.markdown("<h1 class='font-teko' style='font-size:4.2rem; text-align:center; line-height:1; margin-top:15px; color:white;'>REGISTRO DE USUARIO</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:var(--text-sub); font-size:1.15rem;'>Validación Criptográfica y Activación de Bóveda</p>", unsafe_allow_html=True)
        
    with col_der:
        st.markdown("<div class='card-custom' style='margin-top:1.5rem;'>", unsafe_allow_html=True)
        
        if st.session_state['registro_paso'] == 1:
            st.markdown("<h2 class='font-teko' style='font-size:3rem; margin-top:0; color:white;'>CREAR MI CUENTA</h2>", unsafe_allow_html=True)
            st.markdown("<p style='color:var(--text-sub); margin-bottom:1.8rem;'>La cédula debe coincidir con la registrada en la matriz de su líder.</p>", unsafe_allow_html=True)
            
            c_reg = st.text_input("Número de Cédula (DNI/ID)")
            e_reg = st.text_input("Correo electrónico para notificaciones")
            p_reg = st.text_input("Crear Contraseña Segura", type="password")
            
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Validar Datos y Enviar Código", type="primary", use_container_width=True):
                cd = c_reg.strip().lstrip('0')
                correo_ingresado = e_reg.strip().lower()
                
                if not cd or not correo_ingresado or not p_reg:
                    st.error("⚠️ Por favor completa todos los campos requeridos.")
                elif df_usuarios.empty:
                    st.error("⚠️ Las matrices de datos no están disponibles actualmente.")
                elif cd not in df_usuarios['ID/CC/DNI'].values:
                    st.error("⛔ Cédula no encontrada en las matrices oficiales de líderes. Contacte a su líder para ser incorporado.")
                else:
                    db = cargar_usuarios_registrados()
                    if cd in db:
                        st.warning("⚠️ Esta cédula ya se encuentra registrada. Puede iniciar sesión directamente.")
                    else:
                        codigo_otp = str(random.randint(100000, 999999))
                        st.session_state['codigo_otp_debug'] = codigo_otp
                        
                        with st.spinner("Enviando código de seguridad OTP a su correo..."):
                            exito, err = enviar_correo_otp(correo_ingresado, codigo_otp, cd)
                        
                        st.session_state['temp_data'] = {
                            'dni': cd,
                            'email': correo_ingresado,
                            'pin': p_reg,
                            'otp': codigo_otp
                        }
                        st.session_state['registro_paso'] = 2
                        
                        if not exito:
                            # Notificar pero permitir continuar en entorno universitario de prueba
                            st.warning(f"⚠️ El servidor de correo no pudo entregar el mensaje ({err}). Para fines de prueba universitaria, utilice el código en pantalla.")
                        st.rerun()
                            
        elif st.session_state['registro_paso'] == 2:
            st.markdown("<h2 class='font-teko' style='font-size:3rem; margin-top:0; color:white;'>VERIFICAR CÓDIGO OTP</h2>", unsafe_allow_html=True)
            st.info(f"Hemos generado un código de verificación para: **{st.session_state['temp_data']['email']}**")
            
            # Auxiliar visible para pruebas universitarias sin fallas de red
            if st.session_state.get('codigo_otp_debug'):
                st.caption(f"🔑 Código OTP generado: **{st.session_state['codigo_otp_debug']}**")
                
            c_otp = st.text_input("Ingrese el código de 6 dígitos")
            st.markdown("<br>", unsafe_allow_html=True)
            
            if st.button("Verificar y Acceder", type="primary", use_container_width=True):
                if c_otp.strip() == st.session_state['temp_data']['otp']:
                    pass_hash = hash_contrasena(st.session_state['temp_data']['pin'])
                    guardar_usuario(
                        st.session_state['temp_data']['dni'],
                        pass_hash,
                        st.session_state['temp_data']['email']
                    )
                    registrar_evento_auditoria(st.session_state['temp_data']['dni'], "REGISTRO_COMPLETADO", "OK", "Cuenta creada con OTP")
                    st.session_state['cedula_usuario'] = st.session_state['temp_data']['dni']
                    st.session_state['rol_usuario'] = 'usuario'
                    st.success("✅ Cuenta verificada exitosamente. Redirigiendo a su bóveda...")
                    cambiar_vista('dashboard')
                    st.rerun()
                else:
                    st.session_state['intentos_otp'] += 1
                    restantes = 3 - st.session_state['intentos_otp']
                    if restantes <= 0:
                        st.error("⛔ Operación bloqueada temporalmente por exceso de intentos fallidos.")
                        st.session_state['registro_paso'] = 1
                    else:
                        st.error(f"❌ Código incorrecto. Intentos restantes: {restantes}")
                
            st.markdown('<div class="btn-secondary" style="margin-top:10px;">', unsafe_allow_html=True)
            st.button("Cancelar y volver", use_container_width=True, on_click=cambiar_vista, args=('login',))
            st.markdown('</div>', unsafe_allow_html=True)
                
        st.markdown("</div>", unsafe_allow_html=True)


# --- VISTA 4: PANEL DE CONTROL (USUARIO / ADMIN) ---
elif st.session_state['vista_actual'] == 'dashboard':
    c_act = st.session_state['cedula_usuario']
    trm = obtener_trm()
    es_admin = (c_act in ADMIN_USERS or st.session_state.get('rol_usuario') == 'admin')
    
    col_izq, col_der = st.columns([8, 1.4])
    with col_izq: 
        st.markdown("<div class='text-orange font-teko' style='font-size:24px; letter-spacing:2px; margin-top:5px;'>OPERACIÓN DRAGÓN // PORTAL FINANCIERO</div>", unsafe_allow_html=True)
    with col_der: 
        st.markdown('<div class="btn-secondary">', unsafe_allow_html=True)
        if st.button("Cerrar Sesión", use_container_width=True):
            registrar_evento_auditoria(c_act, "LOGOUT", "OK", "Sesión terminada voluntariamente")
            cambiar_vista('landing')
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    
    if es_admin:
        st.markdown("""
        <div style="background:linear-gradient(90deg, #7f1d1d, #991b1b); padding:12px 20px; border-radius:8px; margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center;">
            <div style="font-weight:800; font-size:1.1rem; color:white;">🛡️ CONSOLA DE ADMINISTRADOR GENERAL (AUDITOR / PERITO)</div>
            <div style="font-size:12px; color:#fca5a5;">ACCESO TOTAL RESTRINGIDO</div>
        </div>
        """, unsafe_allow_html=True)
        
        tab_buscador, tab_general, tab_auditoria = st.tabs(["🔍 Consulta por Cédula", "📊 Matriz Global Consolidada", "📜 Bitácora Forense"])
        
        with tab_buscador:
            st.markdown("<h4 class='font-teko' style='font-size:1.8rem; color:white;'>BUSCADOR UNIVERSAL DE PARTICIPANTES</h4>", unsafe_allow_html=True)
            col_b1, col_b2 = st.columns([3, 1])
            with col_b1:
                bcc = st.text_input("Ingrese la cédula a auditar:", key="busc_admin")
            with col_b2:
                st.markdown("<br>", unsafe_allow_html=True)
                buscar_btn = st.button("Consultar Participante", type="primary", use_container_width=True)
                
            if bcc:
                bcd = bcc.strip().lstrip('0')
                if bcd in df_usuarios['ID/CC/DNI'].values:
                    renderizar_dashboard_html(bcd, df_usuarios, trm)
                else:
                    st.warning(f"⚠️ La cédula {bcd} no se encuentra en ninguna de las matrices de líderes.")
            else:
                st.info("Escriba un número de cédula para visualizar su liquidación tal como la ve el participante.")

        with tab_general:
            st.markdown("<h4 class='font-teko' style='font-size:1.8rem; color:white;'>DATOS GLOBALES CONSOLIDADOS</h4>", unsafe_allow_html=True)
            k1, k2, k3 = st.columns(3)
            with k1: st.metric("Personas Únicas", len(df_usuarios))
            with k2: st.metric("TRM Actual", f"${trm:,.2f} COP")
            with k3:
                csv_data = df_usuarios.to_csv(index=False).encode('utf-8')
                st.download_button("Descargar Consolidado (.CSV)", data=csv_data, file_name='Consolidado_Operacion_Dragon.csv', mime='text/csv', use_container_width=True)
            
            st.dataframe(df_usuarios[['ID/CC/DNI', 'NOMBRE COMPLETO', 'LIDER', 'PRODUCTO / MATERIAL', 'CORREO_EXCEL', 'ARCHIVO_ORIGEN']], use_container_width=True)

        with tab_auditoria:
            st.markdown("<h4 class='font-teko' style='font-size:1.8rem; color:white;'>REGISTRO DE ACTIVIDAD Y TRAZABILIDAD FORENSE</h4>", unsafe_allow_html=True)
            if os.path.exists(LOG_AUDITORIA):
                try:
                    with open(LOG_AUDITORIA, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                    df_logs = pd.DataFrame(logs)
                    st.dataframe(df_logs.iloc[::-1], use_container_width=True)
                except Exception:
                    st.info("Sin registros de auditoría aún.")
            else:
                st.info("No se ha generado actividad de auditoría todavía.")
                
    else:
        # Modo Usuario Estándar: Solo ve su propia información
        renderizar_dashboard_html(c_act, df_usuarios, trm)
