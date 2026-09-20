#!/usr/bin/env python3
"""Generate unruly's pinned wordlists.

These files are static build-time data, not scan-time behaviour: the scanner
reads them verbatim, so a scan stays deterministic and reproducible.

The generation rule matters more than the output. Names are produced
COMBINATORIALLY from common prefixes and verbs, never hand-picked to match a
particular target. During development the cloud target's `admin_review_submission`
was the one routine the hint oracle missed; adding that literal string would
have made the eval pass while teaching the tool nothing. Emitting the full
{admin_} x {verbs} cross product is generic — it covers that name the same way
it covers admin_approve, admin_ban and admin_export on projects nobody has
seen.

Regenerate with:  python3 data/gen_wordlists.py
Then commit the .txt files, so scans are reproducible from the repo alone.
"""
from __future__ import annotations
import pathlib

OUT = pathlib.Path(__file__).parent

# ---------------------------------------------------------------- routines
# Privileged routines are the interesting ones: they are usually absent from
# client bundles, so vocabulary harvested from the application never reaches
# them. SECURITY DEFINER routines run with the owner's rights.
ROUTINE_PREFIXES = [
    "admin", "internal", "private", "sys", "mgmt", "ops", "svc", "api",
    "auth", "user", "account", "billing", "report", "job", "task", "cron",
]

ROUTINE_VERBS = [
    "list", "get", "fetch", "search", "find", "count", "summary", "stats",
    "create", "insert", "add", "register", "update", "edit", "modify", "set",
    "delete", "remove", "purge", "prune", "cleanup", "reset", "revoke",
    "review", "approve", "reject", "verify", "confirm", "validate",
    "reorder", "sort", "rank", "promote", "demote", "ban", "unban",
    "export", "import", "sync", "refresh", "rebuild", "recompute",
    "grant", "assign", "invite", "notify", "send", "process", "run",
    "login", "logout", "signup", "impersonate", "elevate", "audit",
]

# Standalone routine names that appear on their own rather than as prefix_verb.
ROUTINE_STANDALONE = [
    "handle_new_user", "handle_updated_at", "set_updated_at", "updated_at",
    "current_user_id", "requesting_user_id", "is_admin", "is_member",
    "has_role", "check_role", "get_claims", "get_my_claims", "jwt_custom_claims",
    "search_all", "global_search", "full_text_search", "healthcheck",
    "get_secret", "decrypt_secret", "rotate_key", "seed_data", "reset_demo",
]


def routines() -> list[str]:
    out = set(ROUTINE_STANDALONE)
    for p in ROUTINE_PREFIXES:
        for v in ROUTINE_VERBS:
            out.add(f"{p}_{v}")
            out.add(f"{v}_{p}")
    return sorted(out)


# ---------------------------------------------------------------- relations
# Used when no application is available to harvest, and as a supplement when
# one is. Kept to genuinely conventional names; domain-specific schemas are the
# hint oracle's job, not a wordlist's.
RELATION_SINGULAR = [
    "user", "profile", "account", "member", "team", "organization", "org",
    "role", "permission", "session", "token", "api_key", "credential",
    "customer", "client", "contact", "lead", "subscriber", "subscription",
    "order", "invoice", "payment", "transaction", "product", "item", "plan",
    "post", "article", "page", "comment", "message", "notification", "email",
    "file", "upload", "document", "image", "media", "attachment", "asset",
    "event", "log", "audit_log", "activity", "history", "record", "entry",
    "setting", "config", "preference", "option", "feature_flag",
    "project", "task", "ticket", "issue", "job", "run", "report", "metric",
    "tag", "category", "label", "review", "rating", "vote", "like",
    "address", "location", "booking", "reservation", "appointment",
    "waitlist", "signup", "submission", "form_response", "feedback", "survey",
]

RELATION_SUFFIXES = ["s", "_archive", "_history", "_log", "_audit", "_backup", "_tmp", "_old"]

# The same handful of things, in the languages people actually name tables in.
#
# Measured on the benchmark corpus: 10-nonlatin-names scored 7% relation
# recall, one of fourteen. That project ships no application, so nothing can be
# harvested and this list IS the recall -- and every name in it was English, so
# a schema whose tables are called пользователи or 顧客 could not be reached at
# all.
#
# Deliberately NOT the corpus's own names. Fitting a wordlist to a benchmark
# measures agreement with the benchmark. These are the dictionary words for
# user, customer, order, product, payment, invoice, message, session, account,
# address, employee, password, file and comment -- the nouns that name a table
# when the team writing it does not work in English.
#
# Bounded, because every entry is a request against somebody's project on every
# scan. Fourteen nouns in nine languages, no suffix expansion: the plural forms
# below are the ones already used as table names, and multiplying them by eight
# suffixes would spend a third of the scan's budget on a case that is rarer
# than the English one.
RELATION_NON_ENGLISH = [
    # Spanish
    "usuarios", "clientes", "pedidos", "productos", "pagos", "facturas",
    "mensajes", "sesiones", "cuentas", "direcciones", "empleados",
    "contraseñas", "archivos", "comentarios",
    # Portuguese
    "usuarios", "usuários", "clientes", "pedidos", "produtos", "pagamentos",
    "faturas", "mensagens", "sessoes", "sessões", "contas", "endereços",
    "funcionarios", "funcionários", "senhas", "arquivos", "comentarios",
    # French
    "utilisateurs", "clients", "commandes", "produits", "paiements",
    "factures", "messages", "sessions", "comptes", "adresses", "employes",
    "employés", "fichiers", "commentaires",
    # German
    "benutzer", "kunden", "bestellungen", "produkte", "zahlungen",
    "rechnungen", "nachrichten", "sitzungen", "konten", "adressen",
    "mitarbeiter", "passwoerter", "passwörter", "dateien", "kommentare",
    # Italian
    "utenti", "clienti", "ordini", "prodotti", "pagamenti", "fatture",
    "messaggi", "sessioni", "conti", "indirizzi", "dipendenti", "file",
    "commenti",
    # Dutch
    "gebruikers", "klanten", "bestellingen", "producten", "betalingen",
    "facturen", "berichten", "sessies", "rekeningen", "adressen",
    "medewerkers", "bestanden", "reacties",
    # Polish
    "uzytkownicy", "użytkownicy", "klienci", "zamowienia", "zamówienia",
    "produkty", "platnosci", "płatności", "faktury", "wiadomosci",
    "wiadomości", "konta", "adresy", "pracownicy", "pliki", "komentarze",
    # Turkish
    "kullanicilar", "kullanıcılar", "musteriler", "müşteriler",
    "siparisler", "siparişler", "urunler", "ürünler", "odemeler",
    "ödemeler", "faturalar", "mesajlar", "hesaplar", "adresler",
    "calisanlar", "çalışanlar", "dosyalar", "yorumlar",
    # Russian
    "пользователи", "клиенты", "заказы", "товары", "платежи", "счета",
    "сообщения", "сессии", "адреса", "сотрудники", "пароли", "файлы",
    "комментарии",
    # Japanese
    "ユーザー", "顧客", "注文", "商品", "支払い", "請求書", "メッセージ",
    "セッション", "アカウント", "住所", "社員", "パスワード", "ファイル",
    # Chinese
    "用户", "客户", "订单", "产品", "支付", "发票", "消息", "会话",
    "账户", "地址", "员工", "密码", "文件", "评论",
    # Korean
    "사용자", "고객", "주문", "상품", "결제", "송장", "메시지", "세션",
    "계정", "주소", "직원", "비밀번호", "파일", "댓글",
]


def relations() -> list[str]:
    out = set()
    for base in RELATION_SINGULAR:
        out.add(base)
        for suf in RELATION_SUFFIXES:
            out.add(base + suf if suf.startswith("_") else base + suf)
    # No suffix expansion for these: see the comment on the list.
    out.update(RELATION_NON_ENGLISH)
    return sorted(out)


# ---------------------------------------------------------------- pages
# Conventional page paths. Needed because an admin console is typically NOT
# linked from the homepage and NOT listed in sitemap.xml -- it is reached by
# people who already know the URL. Frameworks split bundles per page, so the
# JavaScript naming an app's privileged API routes only loads on that page,
# and a pure crawl therefore never sees it.
PAGE_STEMS = [
    "admin", "administrator", "dashboard", "console", "panel", "manage",
    "management", "internal", "staff", "backoffice", "back-office", "ops",
    "operations", "control", "cp", "settings", "config", "account",
    "profile", "billing", "reports", "analytics", "metrics", "logs",
    "audit", "users", "members", "moderation", "review", "queue",
    "debug", "status", "health", "dev", "test", "staging", "preview",
]

PAGE_PREFIXES = ["", "admin/", "internal/", "dashboard/", "app/", "manage/"]


def pages() -> list[str]:
    out = set()
    for stem in PAGE_STEMS:
        out.add("/" + stem)
        for pre in PAGE_PREFIXES:
            if pre:
                out.add("/" + pre + stem)
    return sorted(out)


# ---------------------------------------------------------------- functions
# Edge Function names. Deno functions are deployed by directory name and are
# invoked over HTTP, so they are enumerable exactly like routes. Hyphenated
# kebab-case is the Supabase convention.
FUNCTION_STEMS = [
    "hello", "hello-world", "health", "healthcheck", "ping", "status",
    "webhook", "webhooks", "stripe-webhook", "payment-webhook", "callback",
    "send-email", "send-sms", "send-notification", "notify", "mailer",
    "create-user", "delete-user", "update-user", "sync-user", "on-signup",
    "checkout", "create-checkout-session", "billing", "subscribe",
    "upload", "process-image", "resize-image", "transcode", "export",
    "admin", "admin-api", "internal", "cron", "scheduled", "worker",
    "chat", "completion", "embed", "search", "rag", "ai", "generate",
    "auth", "login", "token", "refresh", "verify", "validate",
    "graphql", "api", "rpc", "proxy", "relay", "ingest", "collect",
]

FUNCTION_AFFIXES = ["", "-v1", "-v2", "-prod", "-dev", "-test", "-staging"]


def functions() -> list[str]:
    out = set()
    for stem in FUNCTION_STEMS:
        for affix in FUNCTION_AFFIXES:
            out.add(stem + affix)
    return sorted(out)


def write(name: str, header: str, items: list[str]) -> None:
    path = OUT / name
    body = "\n".join(f"# {line}" for line in header.strip().splitlines())
    path.write_text(body + "\n\n" + "\n".join(items) + "\n")
    print(f"{name}: {len(items)} entries")


if __name__ == "__main__":
    write("routines.txt", """
        Pinned routine-name wordlist for unruly.
        GENERATED by data/gen_wordlists.py -- do not edit by hand.
        Produced as a cross product of common prefixes and verbs, so it is
        generic by construction rather than fitted to any observed target.
    """, routines())

    write("pages.txt", """
        Pinned page-path wordlist for unruly route discovery.
        GENERATED by data/gen_wordlists.py -- do not edit by hand.
        Conventional console/admin paths, which are typically unlinked and
        absent from sitemap.xml, so crawling alone never reaches the bundles
        that name an application's privileged API routes.
    """, pages())

    write("functions.txt", """
        Pinned Edge Function name wordlist for unruly.
        GENERATED by data/gen_wordlists.py -- do not edit by hand.
        Deno functions are deployed by directory name and invoked over HTTP,
        so they enumerate like routes. Cross product of conventional stems and
        environment affixes.
    """, functions())

    write("relations.txt", """
        Pinned relation-name wordlist for unruly.
        GENERATED by data/gen_wordlists.py -- do not edit by hand.
        Conventional names only. Domain-specific schemas are recovered by the
        PostgREST hint oracle seeded with application vocabulary; a wordlist
        cannot and should not try to guess them.
    """, relations())
