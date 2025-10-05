import os, time, hmac, hashlib, re, json
from typing import Tuple
from flask import Flask, request, abort
from google.auth import default
from google.auth.transport.requests import AuthorizedSession

app = Flask(__name__)

# ======= 基本設定（ENV） =======
PROJECT_ID        = os.environ["PROJECT_ID"]            # 例: light-team-474100-h7
REGION            = os.environ.get("REGION", "asia-northeast1")
JOB_NAME_TEMPLATE = os.environ.get("JOB_NAME_TEMPLATE", "job-{pj}-slackdailyreport")

# 許可する pj のリスト（カンマ区切り、空なら全て許可）
# 例: "pjragnarok,pjshin,pjfb"
ALLOWLIST_PJS     = [p.strip() for p in os.getenv("ALLOWLIST_PJS", "").split(",") if p.strip()]

# 合言葉（グローバル or PJごと）
PASSPHRASE        = os.getenv("PASSPHRASE", "").strip()         # 例: "ローデータ完了"
PASSPHRASE_BY_PJ  = json.loads(os.getenv("PASSPHRASE_BY_PJ", "{}") or "{}")

# Slack 署名検証
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]

# 任意：許可チャンネル（空なら無制限） "C12345,C67890"
CHANNEL_ALLOWLIST = [c.strip() for c in os.getenv("CHANNEL_ALLOWLIST", "").split(",") if c.strip()]


# ======= ヘルパ =======
def verify_slack(req):
    ts = req.headers.get("X-Slack-Request-Timestamp", "")
    sig = req.headers.get("X-Slack-Signature", "")
    if not ts or not sig:
        abort(400, "missing slack headers")
    # 5分以上前のリクエストは拒否
    if abs(time.time() - int(ts)) > 60 * 5:
        abort(400, "timestamp too old")
    basestring = f"v0:{ts}:{req.get_data(as_text=True)}"
    my_sig = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(my_sig, sig):
        abort(401, "signature mismatch")


def parse_pj_and_text(form) -> Tuple[str, str]:
    """
    /prm コマンド専用。
    text は "pj名 残りテキスト" の形式（例: "pjshin ローデータ完了"）
    """
    command = (form.get("command") or "").strip()
    if command != "/gameprm":
        # /gameprm 以外は受け付けない
        return "", (form.get("text") or "").strip()

    text = (form.get("text") or "").strip()
    if not text:
        return "", ""

    parts = text.split()
    pj = parts[0] if parts else ""
    rest = " ".join(parts[1:]).strip() if len(parts) > 1 else ""
    # pj は "pj" で始まる英数字（例: pjshin, pjragnarok）
    if not re.fullmatch(r"pj[a-z0-9]+", pj):
        return "", text
    return pj, rest


def check_passphrase(pj: str, text: str) -> bool:
    # PJごとの合言葉 > グローバル > 未設定（常にOK）
    phrase = PASSPHRASE_BY_PJ.get(pj) or PASSPHRASE
    if not phrase:
        return True
    return re.search(re.escape(phrase), text) is not None


def is_channel_allowed(form) -> bool:
    if not CHANNEL_ALLOWLIST:
        return True
    ch = form.get("channel_id")
    return ch in CHANNEL_ALLOWLIST


def run_job(pj: str):
    region = REGION
    project = PROJECT_ID
    job_name = JOB_NAME_TEMPLATE.format(pj=pj)

    url = (
        f"https://{region}-run.googleapis.com/apis/run.googleapis.com/v1/"
        f"namespaces/{project}/jobs/{job_name}:run"
    )
    creds, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(creds)
    r = session.post(url, json={})
    return r.status_code, r.text


# ======= ルーティング =======
@app.route("/slack", methods=["POST"])
def slack_handler():
    verify_slack(request)

    # チャンネル制限（任意）
    if not is_channel_allowed(request.form):
        return "このチャンネルでは実行できません。", 200

    pj, rest = parse_pj_and_text(request.form)
    if not pj:
        usage = "使い方: `/gameprm pjshin ローデータ完了`"
        return f"pj が見つかりません。{usage}", 200

    if ALLOWLIST_PJS and pj not in ALLOWLIST_PJS:
        return f"許可されていない pj です: `{pj}`", 200

    if not check_passphrase(pj, rest):
        phrase = PASSPHRASE_BY_PJ.get(pj) or PASSPHRASE or "（未設定）"
        return f"違います。`{phrase}` を含めて送ってください。", 200

    status, body = run_job(pj)
    if 200 <= status < 300:
        return f"✅ `{pj}` のジョブを起動しました。数分後に結果がSlackへ投稿されます。", 200
    else:
        return f"⚠️ 起動に失敗しました（{status}）。管理者に連絡してください。\n{body}", 200


@app.route("/")
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
