"""秘密情報の検出ルール。

方針:
- 検出した値は必ずマスクしてレポートに出す（`--reveal-secrets` を明示した場合だけ全文）。
- Firebase の apiKey や Stripe の pk_ など「公開前提」の値はノイズになるので除外する。
"""

from __future__ import annotations

from ..models import Severity
from .base import LineRule

_CREDENTIAL_KEY = r"(?:password|passwd|pwd|secret(?:[_-]?key)?|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)"
# 前に言葉が付いた名前（SMTP_PASSWORD・dbPassword・GOOGLE_CLIENT_SECRET）も見る。名前がキーの語で終わるものだけ
# （passwordField・secretName のように、キーの語で始まるだけの名前は対象外）。引用符の中の名前は - も許す（'X-Api-Key'）
_CREDENTIAL_NAME = r"[A-Za-z0-9_]*" + _CREDENTIAL_KEY
_QUOTED_CREDENTIAL_NAME = r"[A-Za-z0-9_-]*" + _CREDENTIAL_KEY
_Q = r"[\"'`]"  # 値の引用符

# SEC-013 で秘密と見なさない値。当たった部分（名前と値）だけに当てる（同じ行のほかの当たりは見る。マスクは広いまま）
_NOT_A_SECRET = (
    # 値の中に、参照・プレースホルダ・公開前提の値の印がある
    r"(?i:process\.env|os\.getenv|os\.environ|import\.meta\.env|\$\{|your[_-]|django-insecure-|pk_(?:live|test)_|AIza[0-9A-Za-z_-]{35})"
    rf"|(?i:{_Q}(?:password|passwd|secret|test|example|sample|dummy|changeme|placeholder|none|null|true|false|todo|fixme|x{{6,}}|\*{{6,}}){_Q}$)"
    rf"|{_Q}<[^\"'`]*>{_Q}$"  # <your-password>
    # 差し込み口（__API_KEY__）・シェルの変数（"$POSTGRES_PASSWORD"）。値の全体がその形のものだけ（"$uperS3cret!" は外さない）
    rf"|{_Q}(?:__[A-Za-z_]+|\$[A-Za-z_][A-Za-z0-9_]*){_Q}$"
    # URL（user:pass@ の入ったものは外さない）・設定ファイルの env()
    rf"|(?i:{_Q}(?:https?://(?![^\"'`/]*@)|env\())"
    # 次の 5 つは大文字と小文字を区別する（区別しないと Hq7m_W2xT_z9Lp のような本物まで外れる）
    rf"|{_Q}(?:/[a-z0-9_.:-]*)+{_Q}$"  # 道。小文字だけ（/ で始まる base64 は大文字を含む）
    rf"|{_Q}[a-z][a-z_]*(?:\.[a-z_]+)+{_Q}$"  # i18n のキー（auth.password.label）。数字を含む p4ssw0rd.2024 は外さない
    rf"|{_Q}[A-Z]+(?:_[A-Z]+)+{_Q}$"  # 大文字の識別子（RISK_WEAK）。数字を含む ABCD_1234 は外さない
    rf"|{_Q}[a-z]+(?:[-_][a-z]+)+{_Q}$"  # 小文字の単語だけ（local-test-key・current-password）
    # 名前を表す値（newPassword・ResetPassword・auth/RESET_PASSWORD・@app/secret）。camelCase か / で区切ったものだけ
    # （topsecret・supersecretpassword・MySecretP@ss のような弱いパスワードは外さない）
    rf"|{_Q}(?=[^\"'`]*(?i:password|passwd|pwd|secret|token|key))(?:@?[A-Za-z_]+(?:/[A-Za-z_]+)+|[a-z]*(?:[A-Z][a-z]+)+){_Q}$"
    # 前に言葉が付いた名前に、英字だけの値（"showPassword": "Anzeigen" のような画面の文言）
    rf"|(?i:^[\"':]?[A-Za-z0-9_-]+?{_CREDENTIAL_KEY}[\"']?\s*(?::=|=>|[:=])\s*{_Q}[a-z]+{_Q}$)"
    # Laravel の検証ルール（'required|min:8'・'string|min:8|confirmed'・'required_with:…'・'current_password:web'）
    rf"|{_Q}(?:[a-z_]+(?::[^|\"'`]*)?\|)+[a-z_]+(?::[^|\"'`]*)?{_Q}$"
    rf"|{_Q}(?:required\w*|confirmed|current_password|nullable|sometimes|bail)(?::[^|\"'`]*)?{_Q}$"
    rf"|{_Q}\$2[aby]\$\d\d\$"  # bcrypt のハッシュ
    rf"|{_Q}[123]x0{{10,}}[A-Z]{{2}}{_Q}$"  # Cloudflare Turnstile の試験用の秘密（公開されている）
    rf"|{_Q}(?:appl|goog|amzn)_"  # RevenueCat の公開 SDK キー（アプリに入れる前提）
    # ほかのルール（SEC-002・005〜011）が見る形の値。SEC-013 でも出すと「高」を二重に数える
    rf"|{_Q}(?:(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{{16}}|sk_live_[0-9A-Za-z]{{20,}}|gh[pousr]_[A-Za-z0-9]{{36,}}"
    rf"|github_pat_[A-Za-z0-9_]{{50,}}|xox[abprs]-[0-9A-Za-z-]{{10,}}|sk-(?:proj-)?[A-Za-z0-9_-]{{32,}}|sk-ant-[A-Za-z0-9_-]{{20,}}"
    rf"|SG\.[A-Za-z0-9_-]{{16,}}\.[A-Za-z0-9_-]{{16,}}|eyJ[A-Za-z0-9_-]{{8,}}\.[A-Za-z0-9_-]{{8,}}\.[A-Za-z0-9_-]{{8,}}){_Q}$"
)
# 翻訳のファイル（lang/de/validation.php の 'password' => 'Passwort' など）。名前は秘密の語でも、値は画面の文言
_TRANSLATION_FILES = tuple(
    f"{parent}{folder}/*.{ext}"
    for folder in ("lang", "locales", "locale", "i18n", "translations")
    for ext in ("json", "yml", "yaml", "php", "po", "arb")
    for parent in ("", "*/")
)

RULES = [
    LineRule(
        id="SEC-001",
        title="秘密鍵（PRIVATE KEY）がリポジトリに含まれています",
        severity=Severity.CRITICAL,
        category="secret",
        # JSON（サービスアカウントの鍵など）は本文が同じ行に続くので、それも伏せる
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----([^\"'\s]*)",
        message="秘密鍵そのものがコードやリポジトリに含まれています。"
        "漏えいすると署名・復号・サーバーへのログインが可能になります。",
        remediation="鍵を失効・再発行し、秘密管理サービス（1Password / AWS Secrets Manager など）か"
        "環境変数に移してください。git 履歴にも残るため、履歴の書き換えも検討します。",
        cwe="CWE-798",
        owasp="A02:2021",
        secret=True,
        secret_group=1,
        unless=r"\.replace\s*\(|\$\{|PRIVATE KEY-----\.\.\.|(?:example|sample|dummy|placeholder|redacted)",
    ),
    LineRule(
        id="SEC-002",
        title="AWS アクセスキーIDが含まれています",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        message="AWS のアクセスキーIDがハードコードされています。",
        remediation="該当キーを IAM で無効化・削除し、IAM ロールまたは環境変数に切り替えてください。",
        cwe="CWE-798",
        secret=True,
        unless=r"EXAMPLE|example",
    ),
    LineRule(
        id="SEC-003",
        title="AWS シークレットアクセスキーが含まれています",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
        message="AWS のシークレットキーがコードに埋め込まれています。",
        remediation="キーを直ちにローテーションし、Secrets Manager / SSM / 環境変数から読むように変更してください。",
        cwe="CWE-798",
        secret=True,
        secret_group=1,
    ),
    LineRule(
        id="SEC-004",
        title="Google API キーらしき文字列があります",
        severity=Severity.LOW,
        category="secret",
        pattern=r"\bAIza[0-9A-Za-z_-]{35}\b",
        message="Google API キーが含まれています。Firebase の apiKey は公開前提ですが、"
        "制限（HTTP リファラ・API 制限）がないと悪用されます。",
        remediation="Google Cloud Console でキーの API 制限とリファラ制限を設定し、"
        "可能ならサーバー側で扱ってください。",
        cwe="CWE-798",
        secret=True,
        exclude_globs=("google-services.json", "*GoogleService-Info.plist", "*firebase_options.dart"),
    ),
    LineRule(
        id="SEC-005",
        title="Stripe の本番シークレットキーが含まれています",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=r"\bsk_live_[0-9A-Za-z]{20,}\b",
        message="Stripe の本番シークレットキーがコードに含まれています。"
        "決済の操作・返金・顧客情報の取得が可能になります。",
        remediation="Stripe ダッシュボードでキーをロールし、サーバー側の環境変数からのみ読んでください。",
        cwe="CWE-798",
        secret=True,
    ),
    LineRule(
        id="SEC-006",
        title="GitHub トークンが含まれています",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b",
        message="GitHub のアクセストークンがコードに含まれています。リポジトリ操作や"
        "他リポジトリへのアクセスに使われる可能性があります。",
        remediation="GitHub の Settings → Developer settings でトークンを失効させ、"
        "Actions の secrets か環境変数に移してください。",
        cwe="CWE-798",
        secret=True,
        unless=r"x{8,}|X{8,}|example|sample|placeholder",
    ),
    LineRule(
        id="SEC-007",
        title="Slack トークンが含まれています",
        severity=Severity.HIGH,
        category="secret",
        pattern=r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b",
        message="Slack の API トークンが含まれています。ワークスペースのメッセージ読み書きに使えます。",
        remediation="Slack の App 管理画面でトークンを再発行し、環境変数に移してください。",
        cwe="CWE-798",
        secret=True,
    ),
    LineRule(
        id="SEC-008",
        title="OpenAI 形式の API キーが含まれています",
        severity=Severity.HIGH,
        category="secret",
        pattern=r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
        message="OpenAI 形式の API キーがコードに含まれています。利用枠の不正使用につながります。",
        remediation="該当キーを無効化して再発行し、サーバー側の環境変数からのみ読んでください。",
        cwe="CWE-798",
        secret=True,
    ),
    LineRule(
        id="SEC-009",
        title="Anthropic API キーが含まれています",
        severity=Severity.HIGH,
        category="secret",
        pattern=r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        message="Anthropic の API キーがコードに含まれています。",
        remediation="キーを失効・再発行し、サーバー側の環境変数に移してください。",
        cwe="CWE-798",
        secret=True,
    ),
    LineRule(
        id="SEC-010",
        title="SendGrid API キーが含まれています",
        severity=Severity.HIGH,
        category="secret",
        pattern=r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
        message="SendGrid の API キーが含まれています。メール送信の悪用につながります。",
        remediation="SendGrid でキーを削除・再発行し、環境変数に移してください。",
        cwe="CWE-798",
        secret=True,
    ),
    LineRule(
        id="SEC-011",
        title="JWT がハードコードされています",
        severity=Severity.MEDIUM,
        category="secret",
        pattern=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        message="JWT がコードに含まれています。有効期限が長いとセッションの乗っ取りに使えます。",
        remediation="固定トークンをコードから外し、テスト用なら短命のトークンを都度発行してください。",
        cwe="CWE-798",
        secret=True,
    ),
    LineRule(
        id="SEC-012",
        title="認証情報つきの接続URLが含まれています",
        severity=Severity.CRITICAL,
        category="secret",
        pattern=r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps)://[^\s:@/]+:)([^\s@/]+)(@[^\s/]+)",
        message="データベースやメッセージキューの接続URLにパスワードが埋め込まれています。",
        remediation="パスワードを URL から外し、環境変数や Secrets Manager から組み立ててください。",
        cwe="CWE-798",
        secret=True,
        secret_group=2,
        test_severity=Severity.LOW,
        unless=r"(?i)\$\{|<[^>]+>|\{\{|your[_-]|://[^@\s:/]+:(?:pass|passwd|password|secret|changeme|example|test|dev|docker|user|root|admin|postgres|u|p)@|://([^@\s:/]+):\1@",
    ),
    LineRule(
        id="SEC-013",
        title="パスワード／APIキーらしき値がハードコードされています",
        severity=Severity.HIGH,
        category="secret",
        # 値は空白を含まない ASCII だけ（画面の文言「パスワードを入力」「Password must be …」を拾わないため）。
        # 名前の書き方は、"name": / 'name' => （JSON・dict・PHP・Ruby）、Ruby のシンボル :name =>、name = / name: / Go の name :=。
        # => は引用符の名前とシンボルだけ（items.map(password => '…') の矢印関数を拾わないため）
        pattern=r"(?i)(?:[\"']"
        + _QUOTED_CREDENTIAL_NAME
        + r"[\"']\s*(?::=|=>|[:=])|:"
        + _CREDENTIAL_NAME
        + r"\s*=>|\b"
        + _CREDENTIAL_NAME
        + r"\b\s*(?::=|[:=]))\s*"
        + _Q
        # 値の文字にバッククォートを入れない（入れると `a`,password:`b` のように隣の代入までつながる）
        + r"([!#-&(-_a-~]{8,})"
        + _Q,
        message="認証情報らしき文字列が直接書かれています。",
        remediation="値は環境変数かシークレット管理に移し、コードには参照だけを残してください。",
        cwe="CWE-798",
        # .env 形式のファイルは SEC-016 が見る（両方で出すと「高」を二重に数える）
        exclude_globs=(".env", ".env.*", "*.env", ".dev.vars", ".dev.vars.*") + _TRANSLATION_FILES,
        secret=True,
        secret_group=1,
        test_severity=Severity.LOW,
        value_unless=_NOT_A_SECRET,
        tags=("credential",),
    ),
    LineRule(
        id="SEC-014",
        title="npm の認証トークンが含まれています",
        severity=Severity.HIGH,
        category="secret",
        pattern=r"_authToken\s*=\s*([A-Za-z0-9\-_]{20,})",
        message="npm registry の認証トークンがファイルに含まれています。",
        remediation="トークンを無効化し、CI では NODE_AUTH_TOKEN などの環境変数を使ってください。",
        cwe="CWE-798",
        secret=True,
        secret_group=1,
    ),
    LineRule(
        id="SEC-015",
        title="YAML にパスワード／トークンが平文で書かれています",
        severity=Severity.HIGH,
        category="secret",
        # キーが password / secret / token / api_key で終わり、値が引用符なしで続くもの。
        # ${{ }}・*別名・&アンカー・| などの記法、secretName のようなキーは対象外
        pattern=r"(?i)^\s*-?\s*[\w.-]*(?:password|passwd|secret|token|api[_-]?key)\s*:\s*([A-Za-z0-9_./+=@~^-][!#-&(-~]{7,})\s*$",
        languages=("yaml",),
        message="設定ファイルに認証情報が平文で書かれています。",
        remediation="値は環境変数やシークレット管理（GitHub Actions なら secrets）から渡してください。",
        cwe="CWE-798",
        secret=True,
        secret_group=1,
        test_severity=Severity.LOW,
        unless=r"(?i)\$\{|\{\{|<[^>]*>|your[_-]|change[_-]?me|example|sample|dummy|placeholder|x{6,}"
        r"|:\s*(?:password|passwd|secret|postgres|root|admin|test|dev|docker|user|true|false|null|none)\s*$",
    ),
    LineRule(
        id="SEC-016",
        title=".env 形式のファイルに秘密情報が書かれています",
        severity=Severity.HIGH,
        category="secret",
        # コメントにした行（# OLD_DB_PASSWORD=…）・行末のコメント・名前の - と _PWD も見る（SEC-013 は .env を見ないため）。
        # PWD だけの名前は、シェルの今のフォルダなので見ない
        pattern=r"(?i)^\s*(?:#\s*)?(?:export\s+)?[A-Za-z0-9_-]*(?:PASSWORD|PASSWD|_PWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE_KEY|ACCESS_KEY)"
        r"\s*=\s*[\"']?([!#-&(-~]{8,}?)[\"']?(?:\s+#.*)?\s*$",
        path_globs=(".env", ".env.*", "*.env", ".dev.vars", ".dev.vars.*"),
        message="環境変数ファイルに認証情報が書かれています。リポジトリに含めると履歴からも読めます。",
        remediation="ファイルを git から外して値をローテーションし、.env.example には空の値かダミーだけを書いてください。",
        cwe="CWE-798",
        secret=True,
        secret_group=1,
        test_severity=Severity.LOW,
        unless=r"(?i)\$\{|<[^>]*>|your[_-]|change[_-]?me|replace[_-]?me|example|sample|dummy|placeholder|x{6,}|\*{6,}"
        r"|=\s*[\"']?(?:password|passwd|secret|postgres|root|admin|test|dev|docker)[\"']?\s*$",
    ),
]
