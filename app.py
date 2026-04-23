import os
import re
import time
import base64
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
load_dotenv()

app = Flask(__name__)

ORG_ID               = os.getenv("ORG_ID", "316432")
MERAKI_API_KEY       = os.getenv("MERAKI_API_KEY", "")
FRESHDESK_API_KEY    = os.getenv("FRESHDESK_API_KEY", "")
FRESHDESK_SUBDOMAIN  = os.getenv("FRESHDESK_SUBDOMAIN", "")

MERAKI_HEADERS = {
    "X-Cisco-Meraki-API-Key": MERAKI_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# ---------------------------------------------------------------------------
# MAPPING COLEGIO → NOMBRE DE RED MERAKI
# ---------------------------------------------------------------------------
COLEGIO_TO_NETWORK_NAME = {
    "SIP CENTRAL":                   "SIP Central",
    "Arturo Matte Larraín Básica":   "Red - AMLB",
    "Arturo Matte Larrain Media":    "Red - AMLM",
    "Arturo Toro Amor":              "Red - ATA",
    "Claudio Matte Pérez":           "Red - CM",
    "Elvira Hurtado de Matte":       "Red - EHM",
    "Eliodoro Matte Ossa":           "Red - EMO",
    "Francisco Arriarán":            "Red - FA",
    "Francisco Olea":                "Red - FO",
    "Guillermo Matta":               "Red - GM",
    "Instituto Hermanos Matte":      "Red - IHM",
    "José Agustín Alfonso":          "Red - JAA",
    "Jorge Alessandri Rodríguez":    "Red - JAR",
    "José Joaquín Prieto":           "Red - JJP",
    "Liceo Bicentenario Italia":     "Red - LBI",
    "Los Nogales":                   "Red - LN",
    "Presidente Alessandri":         "Red - PA",
    "Rosa Elvira Matte":             "Red - REM",
    "Rafael Sanhueza Lizardi":       "Red - RSL",
}

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# ---------------------------------------------------------------------------
# HELPERS GENÉRICOS
# ---------------------------------------------------------------------------
def normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower().replace("-", ":")

def is_valid_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac))

def http_json(method, url, *, headers=None, params=None, json=None, timeout=15):
    """
    Ejecuta una request HTTP con reintento básico por rate-limit (429).
    Retorna (status_code, json_body_or_text).
    """
    for attempt in range(3):
        try:
            r = requests.request(
                method, url,
                headers=headers,
                params=params,
                json=json,
                timeout=timeout,
            )
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", "2"))
                print(f"[rate-limit] esperando {wait}s (intento {attempt+1}/3)")
                time.sleep(wait)
                continue
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, r.text
        except requests.exceptions.RequestException as e:
            print(f"[http_json] error de red: {e}")
            return 503, {"error": str(e)}
    return 429, {"error": "rate_limited_after_retries"}

# ---------------------------------------------------------------------------
# HELPERS MERAKI
# ---------------------------------------------------------------------------
def meraki_get_networks():
    url = f"https://api.meraki.com/api/v1/organizations/{ORG_ID}/networks"
    return http_json("GET", url, headers=MERAKI_HEADERS)

def meraki_get_org_admins():
    """
    Los admins en Meraki son a nivel de ORGANIZACIÓN, no de red individual.
    GET /organizations/{orgId}/admins
    """
    url = f"https://api.meraki.com/api/v1/organizations/{ORG_ID}/admins"
    return http_json("GET", url, headers=MERAKI_HEADERS)

def meraki_get_policies(network_id):
    url = f"https://api.meraki.com/api/v1/networks/{network_id}/groupPolicies"
    return http_json("GET", url, headers=MERAKI_HEADERS)

def meraki_get_client(network_id, client_id):
    url = f"https://api.meraki.com/api/v1/networks/{network_id}/clients/{client_id}"
    return http_json("GET", url, headers=MERAKI_HEADERS)

def meraki_apply_policy(network_id, client_id, group_policy_id):
    url = f"https://api.meraki.com/api/v1/networks/{network_id}/clients/{client_id}/policy"
    payload = {
        "devicePolicy": "Group policy",
        "groupPolicyId": str(group_policy_id),
    }
    return http_json("PUT", url, headers=MERAKI_HEADERS, json=payload)

def get_network_id_by_colegio(colegio, networks):
    wanted_name = COLEGIO_TO_NETWORK_NAME.get(colegio)
    if not wanted_name:
        return None
    for net in networks or []:
        if net.get("name") == wanted_name:
            return net.get("id")
    return None

def admin_tiene_acceso(admin: dict, network_id: str) -> bool:
    if admin.get("orgAccess") in ("full", "read-only", "observer"):
        return True
    redes_con_acceso = [t.get("id") for t in admin.get("networks", [])]
    return network_id in redes_con_acceso

# ---------------------------------------------------------------------------
# HELPERS FRESHDESK
# ---------------------------------------------------------------------------
def _freshdesk_headers():
    """
    Freshdesk usa HTTP Basic Auth: base64(API_KEY:X)
    La 'X' es literal — Freshdesk no necesita contraseña real.
    """
    token = base64.b64encode(f"{FRESHDESK_API_KEY}:X".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
    }

def freshdesk_reply_ticket(ticket_id: str, mensaje: str):
    """
    Agrega una respuesta pública al ticket en Freshdesk.
    POST /api/v2/tickets/{id}/reply
    """
    url = f"https://{FRESHDESK_SUBDOMAIN}.freshdesk.com/api/v2/tickets/{ticket_id}/reply"
    payload = {"body": mensaje}
    return http_json("POST", url, headers=_freshdesk_headers(), json=payload)

def freshdesk_close_ticket(ticket_id: str):
    """
    Cierra el ticket en Freshdesk (status 5 = Closed).
    PUT /api/v2/tickets/{id}
    """
    url = f"https://{FRESHDESK_SUBDOMAIN}.freshdesk.com/api/v2/tickets/{ticket_id}"
    payload = {"status": 5}
    return http_json("PUT", url, headers=_freshdesk_headers(), json=payload)

# ---------------------------------------------------------------------------
# ENTRY POINT — compatible con Flask local Y Google Cloud Functions
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "running", "hint": "usar /webhook/freshdesk"}), 200


@app.route("/webhook/freshdesk", methods=["GET"])
def webhook_freshdesk(request=None):
    """
    Webhook principal.
    - En Flask local:        el decorador @app.route inyecta el request de Flask.
    - En Google Cloud Func:  GCF llama directamente a esta función pasando request.
    El parámetro `request=None` permite ambos modos sin cambiar código.
    """
    # --- Soporte dual Flask / GCF ---
    if request is None:
        from flask import request as flask_request
        request = flask_request

    # -----------------------------------------------------------------------
    # 1. Leer y validar parámetros
    # -----------------------------------------------------------------------
    correo    = (request.args.get("correo")    or "").strip().lower()
    ticket_id = (request.args.get("ticket_id") or "").strip()
    mac       = normalize_mac(request.args.get("mac"))
    politica  = (request.args.get("politica")  or "").strip()
    colegio   = (request.args.get("colegio")   or "").strip()

    print(">>> WEBHOOK recibido:", {
        "correo": correo,
        "ticket_id": ticket_id,
        "mac": mac,
        "politica": politica,
        "colegio": colegio,
    })

    if not all([correo, ticket_id, mac, politica, colegio]):
        return jsonify({
            "error": "missing_params",
            "recibidos": {
                "correo":    bool(correo),
                "ticket_id": bool(ticket_id),
                "mac":       bool(mac),
                "politica":  bool(politica),
                "colegio":   bool(colegio),
            }
        }), 400

    if not is_valid_mac(mac):
        return jsonify({"error": "invalid_mac", "mac": mac}), 400

    if not MERAKI_API_KEY:
        return jsonify({"error": "MERAKI_API_KEY no configurada"}), 500

    if not FRESHDESK_API_KEY or not FRESHDESK_SUBDOMAIN:
        return jsonify({"error": "FRESHDESK_API_KEY o FRESHDESK_SUBDOMAIN no configurados"}), 500

    # -----------------------------------------------------------------------
    # 2. Obtener redes de Meraki y buscar la del colegio
    # -----------------------------------------------------------------------
    st, networks = meraki_get_networks()
    if st != 200:
        return jsonify({"error": "meraki_networks_failed", "status": st, "detalle": networks}), 502

    network_id = get_network_id_by_colegio(colegio, networks)
    if not network_id:
        return jsonify({
            "error": "red_no_encontrada",
            "colegio": colegio,
            "hint": f"Verifica que '{colegio}' exista en COLEGIO_TO_NETWORK_NAME"
        }), 404

    # -----------------------------------------------------------------------
    # 3. Verificar que el solicitante sea admin con acceso a esa red
    #    (Los admins en Meraki son a nivel de organización, no de red)
    # -----------------------------------------------------------------------
    st, admins = meraki_get_org_admins()
    if st != 200:
        return jsonify({"error": "meraki_admins_failed", "status": st, "detalle": admins}), 502

    # Construir lista de emails que tienen acceso a esta red específica
    emails_con_acceso = [
        a.get("email", "").strip().lower()
        for a in (admins or [])
        if admin_tiene_acceso(a, network_id)
    ]

    print(f"[auth] admins con acceso a {network_id}: {emails_con_acceso}")

    if correo not in emails_con_acceso:
        return jsonify({
            "error": "no_autorizado",
            "correo": correo,
            "hint": "El correo no tiene acceso a la red de ese colegio en Meraki"
        }), 403

    # -----------------------------------------------------------------------
    # 4. Verificar que la política de navegación exista en esa red
    # -----------------------------------------------------------------------
    st, policies = meraki_get_policies(network_id)
    if st != 200:
        return jsonify({"error": "meraki_policies_failed", "status": st, "detalle": policies}), 502

    policy_obj = next(
        (p for p in (policies or []) if p.get("name", "").strip().lower() == politica.lower()),
        None,
    )
    if not policy_obj:
        politicas_disponibles = [p.get("name") for p in (policies or [])]
        return jsonify({
            "error": "politica_no_encontrada",
            "politica_buscada": politica,
            "politicas_disponibles": politicas_disponibles,
        }), 404

    group_policy_id = policy_obj.get("groupPolicyId")
    if group_policy_id is None:
        return jsonify({"error": "policy_sin_groupPolicyId", "policy": policy_obj}), 500

    # -----------------------------------------------------------------------
    # 5. Verificar que el cliente (MAC) existe en la red
    # -----------------------------------------------------------------------
    st, client = meraki_get_client(network_id, mac)
    if st == 404:
        return jsonify({
            "error": "cliente_no_encontrado",
            "mac": mac,
            "hint": "El dispositivo no aparece en los clientes recientes de esta red"
        }), 404
    if st != 200:
        return jsonify({"error": "client_lookup_failed", "status": st, "detalle": client}), 502

    # -----------------------------------------------------------------------
    # 6. Aplicar la política en Meraki
    # -----------------------------------------------------------------------
    st, resp = meraki_apply_policy(network_id, mac, group_policy_id)
    if st not in (200, 201):
        return jsonify({"error": "apply_policy_failed", "status": st, "detalle": resp}), 502

    print(f"[OK] Política '{politica}' aplicada → MAC {mac} en red {network_id}")

    # -----------------------------------------------------------------------
    # 7. Responder el ticket en Freshdesk con mensaje de éxito
    # -----------------------------------------------------------------------
    mensaje_fd = (
        f"✅ <b>Política de navegación aplicada correctamente.</b><br><br>"
        f"<b>Colegio:</b> {colegio}<br>"
        f"<b>Política aplicada:</b> {politica}<br>"
        f"<b>Dispositivo (MAC):</b> {mac}<br><br>"
        f"Este cambio fue realizado de forma automática por el sistema."
    )
    st_reply, resp_reply = freshdesk_reply_ticket(ticket_id, mensaje_fd)
    if st_reply not in (200, 201):
        print(f"[WARN] No se pudo responder el ticket {ticket_id}: {st_reply} {resp_reply}")

    # -----------------------------------------------------------------------
    # 8. Cerrar el ticket en Freshdesk
    # -----------------------------------------------------------------------
    st_close, resp_close = freshdesk_close_ticket(ticket_id)
    if st_close not in (200, 201):
        print(f"[WARN] No se pudo cerrar el ticket {ticket_id}: {st_close} {resp_close}")

    # -----------------------------------------------------------------------
    # Respuesta final al webhook
    # -----------------------------------------------------------------------
    return jsonify({
        "status": "ok",
        "ticket_id": ticket_id,
        "network_id": network_id,
        "colegio": colegio,
        "politica_aplicada": politica,
        "mac": mac,
        "freshdesk_reply": st_reply,
        "freshdesk_close": st_close,
    }), 200


# ---------------------------------------------------------------------------
# ARRANQUE LOCAL
# En Google Cloud Functions este bloque es ignorado automáticamente.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)