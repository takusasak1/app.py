import os
import re
import json
import time
import hmac
import hashlib
import threading
from typing import Tuple

from flask import Flask, request
from google.auth import default
from google.auth.transport.requests import AuthorizedSession

app = Flask(__name__)

# =========================
# 環境変数（未設定でも落ちないように getenv を使用）
# =========================
PROJECT_ID        = os.getenv("PROJECT_ID", "")             # 例: light-team-474100-h7
REGION            = os.getenv("REGION", "asia-northeast1")
JOB_NAME_TEMPLATE = os.getenv("JOB_NAME_TEMPLATE", "job-{pj}-slackdailyreport")

# Slack 認証（Slack App 推奨：Signing Secret）
SLACK_SIGNING_SECRET     = os.getenv("SLACK_SIGNING_SECRET", "")
# （旧Custom Integration用・使わないなら未設定でOK）
SLACK_VERIFICATION_TOKEN = os.getenv("SLACK_VERIFICATION_TOKEN", "")

# オプション（運用ガード）
ALLOWLIST_PJS = [p.strip() for p in os.getenv("ALLOWLIST_PJS", "").split(",") if p.strip()]
PASSPHRASE    = os.getenv("PASSPHRASE", "").strip()  # 例: ローデータ完了
# 例: {"pjshin": "ローデータ完了", "pjragnarok": "ready"}
PASSPHRASE_BY_PJ = json.loads(os.getenv("PASSPHRASE_BY_PJ", "{}") or "{}")
CHANNEL_ALLOWLIST = [c.strip() for c in os.getenv("CHANNEL_ALLOWLIST", "").split(",") if c.strip()]

# 起動時に致命傷にならないように、未設定は警告ログだけ
if not PROJECT_ID:
    print("[WARN] PROJECT_ID is not set; run_job will fail until it's configured.")
if not SLACK_SIGNING_SECRET and not SLACK_VERIFICATION_TOKEN:
    print("[WARN] No Slack auth configured (SIGNING_SECRET or VERIFICATION_TOKEN).")

# =========================
# ヘルパ関数
# =========================
def parse_pj_and_text(form) -> Tuple[str, str]:
    """
    /gameprm コマンド前提。
    text は「pj名 残りテキスト」の形式（例: "pjshin ローデータ完了"）
    """
    command = (form.get("command") or "").strip()
    if command != "/gameprm":
        return "", (form.get("text") or "").strip()

    text = (form.get("text") or "").strip()
    if not text:
        return "", ""

    parts = text.split()
    pj = parts[0] if parts else ""
    rest = " ".join(parts[1:]).strip() if len(parts) > 1 else ""
    # pj は "pj"で始まる英数字（例: pjshin, pjragnarok）
    if not re.fullmatch(r"pj[a-z0-9]+", pj):
        return "", text
    return pj, rest


def is_channel_allowed(form) -> bool:
    if not CHANNEL_ALLOWLIST:
        return True
    ch = form.get("channel_id")
    return ch in CHANNEL_ALLOWLIST


def check_passphrase(pj: str, text: str) -> bool:
    # PJごとの合言葉 > グローバル > 未設定（常にOK）
    phrase = PASSPHRASE_BY_PJ.get(pj) or PASSPHRASE
    if not phrase:
        return True
    return re.search(re.escape(phrase), text) is not None


def verify_slack(req):
    """
    Slack App（Signing Secret）優先で検証。
    旧Custom Integration（Verification Token）にもフォールバック対応。
    条件を満たせない場合は例外を投げる（呼び元で握る）。
    """
    # 新方式（Slack App）: 署名ヘッダ検証
    sig = req.headers.get("X-Slack-Signature")
    ts  = req.headers.get("X-Slack-Request-Timestamp")
    if sig and ts and SLACK_SIGNING_SECRET:
        # リプレイ対策：5分以内
        if abs(time.time() - int(ts)) > 60 * 5:
            raise ValueError("timestamp too old")
        basestring = f"v0:{ts}:{req.get_data(as_text=True)}"
        my_sig = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), basestring.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(my_sig, sig):
            raise ValueError("signature mismatch")
        return

    # 旧方式（Custom Integration）: Verification Token
    token = (req.form.get("token") or req.values.get("token") or "").strip()
    if SLACK_VERIFICATION_TOKEN and token == SLACK_VERIFICATION_TOKEN:
        return

    raise ValueError("no valid slack auth (missing headers or token mismatch)")


def run_job(pj: str):
    """
    Cloud Run Job を起動。
    """
    region = REGION
    project = PROJECT_ID
    job_name = JOB_NAME_TEMPLATE.format(pj=pj)

    if not project:
        print("[ERROR] PROJECT_ID is empty; aborting run_job.")
        return

    url = (
        f"https://{region}-run.googleapis.com/apis/run.googleapis.com/v1/"
        f"namespaces/{project}/jobs/{job_name}:run"
    )
    creds, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(creds)
    r = session.post(url, json={})
    print(f"[run_job] POST {url} -> {r.status_code}")
    if r.status_code >= 300:
        print(f"[run_job] Response: {r.text}")


# =========================
# ルーティング
# =========================
@app.route("/slack", methods=["POST"])
def slack_handler():
    # --- 署名検証：失敗しても Slack には200で応答し、dispatch_failedを避ける ---
    try:
        verify_slack(request)
    except Exception as e:
        print("SLACK VERIFY ERROR:", repr(e))
        # デバッグ：必要に応じてヘッダ/ボディも記録（過剰ログに注意）
        # print("Headers:", {k: v for k, v in request.headers.items() if k.startswith("X-Slack")})
        # print("Body:", request.get_data(as_text=True)[:500])
        return "署名検証エラー。Signing Secret と Request URL（/slack）を確認してください。", 200

    # --- チャンネル制限（任意） ---
    if not is_channel_allowed(request.form):
        return "このチャンネルでは実行できません。", 200

    # --- 入力パース ---
    pj, rest = parse_pj_and_text(request.form)
    if not pj:
        return "使い方: `/gameprm pjshin ローデータ完了`", 200

    if ALLOWLIST_PJS and pj not in ALLOWLIST_PJS:
        return f"許可されていない pj です: `{pj}`", 200

    if not check_passphrase(pj, rest):
        phrase = PASSPHRASE_BY_PJ.get(pj) or PASSPHRASE or "（未設定）"
        return f"愛言葉が違います。`{phrase}` を含めて送ってください。", 200

    # --- 即時ACKし、裏でジョブ起動（3秒ルール対策） ---
    threading.Thread(target=run_job, args=(pj,), daemon=True).start()
    return f"✅ `{pj}` のジョブ起動リクエストを受け付けました。数分後に結果がSlackへ投稿されます。", 200


@app.route("/")
def health():
    return "ok", 200


if __name__ == "__main__":
    # Cloud Run 環境では gunicorn 等から呼ばれる想定だが、ローカル動作用に記載
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
