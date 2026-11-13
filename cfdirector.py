#!/usr/bin/env python3
"""Cloudflaredirector (cfdirector): header-gated Worker (public domain) -> Access-protected tunnel hostname -> local origin.
Also supports internal-only services: no Worker/public domain, reachable directly at their
Access-protected tunnel hostname (gated by your own Cloudflare Access login, not a header).

  ./cfdirector.py up   cdn.example.com tun.example.com -H X-TEST-HEADER:TEST123 -o https://localhost:8443
  ./cfdirector.py up -H X-TEST-HEADER:TEST123           # omit domain/tunnel_host, pick from your zones
  ./cfdirector.py up cdn1.example.com tun1.example.com -H X:v -o http://localhost:443 \\
      --service cdn2.example.com,tun2.example.com,http://localhost:8087 \\
      --internal admin.internal.example.com,http://localhost:9000
  ./cfdirector.py down tun.example.com   # name the FIRST service's tunnel_host of a multi-service `up`

Multiple local services can share one tunnel: the positional domain/tunnel_host/-o is the
first service, each --service DOMAIN,TUNNEL_HOST,ORIGIN adds another external (public, header
+Worker-gated) one, each --internal TUNNEL_HOST,ORIGIN adds one with no public domain at all
(Access-login-gated only). All share the one cloudflared process and one tunnel.

Once up, you get a `cfdirector>` prompt to add/remove services and edit the header/geo/redirect live,
without restarting the tunnel (cloudflared picks up a changed ingress on the fly). Type `help`
at the prompt for commands.

`up` builds whatever is missing and reuses what's already there on a rerun. What exists is
tracked in state/<first-tunnel_host>.json (0600). Config comes from .env (see .env.example).
Worker deploy uses wrangler; you're prompted to `wrangler login` if needed.
"""
import argparse, json, os, secrets, shlex, shutil, signal, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path
try:
    import readline  # noqa: F401 -- importing it is enough: input() then gets history (up/down)
except ImportError:  # not available on plain Windows without pyreadline3
    readline = None

HERE = Path(__file__).resolve().parent
API = "https://api.cloudflare.com/client/v4"

# without a tty, stdout is block-buffered: our prints would sit unflushed in memory for as
# long as cloudflared keeps running below (which is indefinite), hiding them from a redirected
# log. Force line buffering so each print lands immediately regardless of destination.
sys.stdout.reconfigure(line_buffering=True)

_TTY = sys.stdout.isatty()
GREEN, YELLOW, RED, RESET = ("\033[32m", "\033[33m", "\033[31m", "\033[0m") if _TTY else ("", "", "", "")
ORANGE = "\033[38;5;208m" if _TTY else ""
PROMPT = f"{ORANGE}cfdirector> {RESET}"


def status_color(code):
    color = GREEN if code and 200 <= code < 300 else YELLOW if code and 300 <= code < 400 else RED
    return f"{color}{code if code else 'ERR'}{RESET}"


TRANSIENT_EDGE_CODES = {403, 503, 522, 523, 525, 526, 530}  # route/cert still propagating


def http_status(url, headers=None, retries=8, delay=4):
    """New DNS/routes need a few seconds to propagate right after deploy; retry on connection
    failures and on edge-level codes a still-propagating custom domain can throw -- but not on
    a definitive answer (e.g. 404/302 from our own Worker logic) so the common case is instant."""
    code = None
    # Cloudflare's own bot rules block urllib's default "Python-urllib/x.y" UA (error 1010)
    # before the request ever reaches the Worker; a normal UA avoids that false negative.
    req_headers = {"User-Agent": "curl/8.0", **(headers or {})}
    for attempt in range(retries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=req_headers), timeout=10).status
        except urllib.error.HTTPError as e:
            code = e.code
            if code not in TRANSIENT_EDGE_CODES:
                return code
        except Exception:
            code = None
        if attempt < retries - 1:
            time.sleep(delay)
    return code

for line in (HERE / ".env").read_text().splitlines() if (HERE / ".env").exists() else []:
    k, sep, v = line.partition("=")
    if sep and not k.lstrip().startswith("#"):
        os.environ.setdefault(k.strip(), v.strip().strip("\"'"))
try:
    TOKEN, ACCT = os.environ["CF_API_TOKEN"], os.environ["CF_ACCOUNT_ID"]
except KeyError as e:
    sys.exit(f"{RED}{e.args[0]} missing: add it to {HERE / '.env'} (see .env.example){RESET}")
# Access policy for internal-only services (no Worker to carry a service token, so these are
# gated by your own Cloudflare Access login instead). Override in .env if needed.
OWNER_EMAIL = os.environ.get("OWNER_EMAIL")  # required only for --internal services


def cf(method, path, body=None, soft=False):
    """soft=True: a 404 (already gone) returns None instead of exiting."""
    req = urllib.request.Request(API + path, json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={"Authorization": f"Bearer {TOKEN}",
                                                         "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req))["result"]
    except urllib.error.HTTPError as e:
        if soft and e.code == 404:
            return None
        sys.exit(f"{RED}{method} {path} -> {status_color(e.code)}: {e.read().decode()}{RESET}")


def zone_id(host):
    # zone = last two labels; breaks on .co.uk etc, add --zone if needed
    z = cf("GET", f"/zones?name={'.'.join(host.split('.')[-2:])}")
    return z[0]["id"] if z else sys.exit(f"{RED}no zone for {host} in this account{RESET}")


# wrangler uses its own OAuth login, so keep our API token out of its environment
WENV = {k: v for k, v in os.environ.items() if k not in ("CLOUDFLARE_API_TOKEN", "CF_API_TOKEN")}
WENV["CLOUDFLARE_ACCOUNT_ID"] = ACCT


def wrangler(*args, cwd=None, stdin=None, check=True, capture=False):
    # Default cwd is deliberately NOT `HERE`: wrangler auto-loads a .env from its cwd, and
    # ours holds CF_API_TOKEN, which wrangler treats as its own (deprecated) auth var and
    # tries first -- that token has no Workers permission (wrangler uses OAuth for that),
    # so any call left at the default cwd would silently misauthenticate. Callers that need
    # the Worker project dir (deploy, secret bulk) pass cwd=wdir explicitly.
    return subprocess.run(["wrangler", *args], cwd=cwd or tempfile.gettempdir(), env=WENV,
                          input=stdin, text=True, check=check, capture_output=capture)


def ensure_wrangler_login():
    if not shutil.which("wrangler"):
        sys.exit(f"{RED}wrangler not found: npm install -g wrangler{RESET}")
    if wrangler("whoami", check=False).returncode == 0:
        return
    input("\nNot signed in to wrangler. Press Enter to run `wrangler login`...\n"
          "(headless host: open the URL on your machine, then run the failing localhost:8976 "
          "callback URL with curl on this host)\n")
    wrangler("login")


WORKER = """export default {
  async fetch(request, env) {
    const headerOk = request.headers.get(env.GATE_NAME) === env.GATE_VALUE;
    const allowed = env.ALLOWED_COUNTRIES ? env.ALLOWED_COUNTRIES.split(",") : null;
    const geoOk = !allowed || allowed.includes(request.cf?.country);
    if (!headerOk || !geoOk) {
      if (env.REDIRECT_URL) return Response.redirect(env.REDIRECT_URL, 302);
      return new Response("Not Found", { status: 404 });
    }
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    headers.delete(env.GATE_NAME);
    headers.set("CF-Access-Client-Id", env.CF_ACCESS_CLIENT_ID);
    headers.set("CF-Access-Client-Secret", env.CF_ACCESS_CLIENT_SECRET);
    return fetch(new Request("https://" + env.TUNNEL_HOST + url.pathname + url.search,
      { method: request.method, headers, body: request.body, redirect: "manual" }));
  }
};
"""


class State(dict):
    """Keyed by tunnel_host (not domain) in self.path's filename, since an internal service has
    no domain. self["services"] maps tunnel_host -> that service's record (its "domain" key is
    None for an internal one)."""
    def __init__(self, slug):
        self.path = HERE / "state" / f"{slug}.json"
        super().__init__(json.loads(self.path.read_text()) if self.path.exists() else {})

    def save(self):
        self.path.parent.mkdir(exist_ok=True)
        self.path.write_text(json.dumps(self, indent=2))
        self.path.chmod(0o600)


def pick_hostname(kind, zones, example="cdn"):
    print(f"\nNo {kind} given. Zones available to this token:")
    for i, z in enumerate(zones, 1):
        print(f"  {i}. {z}")
    while True:
        choice = input(f"Pick a zone [1-{len(zones)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(zones):
            break
    label = input(f"Subdomain label for {kind} (e.g. {example}): ").strip().strip(".")
    return f"{label}.{zones[int(choice) - 1]}"


def parse_services(a):
    """Returns [{"domain" (None if internal), "tunnel_host", "origin"}, ...]. The positional
    domain/tunnel_host/-o (if either is given) gives the first (external) service. A fully bare
    `up -H ...` (no positional, no --service/--internal) instead prompts interactively -- kind,
    tunnel hostname, origin, and domain if external -- for the first service too (not just
    additional ones), and keeps offering to add more. Each --service DOMAIN,TUNNEL_HOST,ORIGIN
    or --internal TUNNEL_HOST,ORIGIN adds another one sharing the same tunnel."""
    services = []
    zones = []

    def get_zones():
        nonlocal zones
        if not zones:
            zones = sorted({z["name"] for z in cf("GET", "/zones") if z["account"]["id"] == ACCT})
            if not zones:
                sys.exit(f"{RED}no zones visible to this token{RESET}")
        return zones

    def prompt_service(default_origin=None):
        kind = input("Kind -- (e)xternal [public domain] or (i)nternal [Access-login only]? [e]: ").strip().lower()
        th = pick_hostname("tunnel hostname", get_zones(), example="tunnel")
        o = default_origin if default_origin is not None else (
            input("Local origin for this service [http://localhost:80]: ").strip() or "http://localhost:80")
        d = None if kind.startswith("i") else pick_hostname("public Worker domain", get_zones())
        return {"domain": d, "tunnel_host": th, "origin": o}

    extra_given = bool(a.service or a.internal)
    if a.domain is None and a.tunnel_host is None and not extra_given:
        # fully bare: ask kind/tunnel_host/origin/domain for the first service too, not just
        # additional ones -- -o's default only applies if the user actually passed -o
        services.append(prompt_service(default_origin=a.origin))
        while input("\nAdd another service to this tunnel? [y/N] ").strip().lower().startswith("y"):
            services.append(prompt_service())
    elif not extra_given or a.domain is not None or a.tunnel_host is not None:
        if a.domain is None:
            a.domain = pick_hostname("public Worker domain", get_zones())
        if a.tunnel_host is None:
            a.tunnel_host = pick_hostname("tunnel hostname", get_zones(), example="tunnel")
        services.append({"domain": a.domain, "tunnel_host": a.tunnel_host, "origin": a.origin or "http://localhost:80"})
    for spec in a.service:
        parts = [p.strip() for p in spec.split(",")]
        if len(parts) != 3:
            sys.exit(f"{RED}--service needs DOMAIN,TUNNEL_HOST,ORIGIN (got: {spec}){RESET}")
        services.append(dict(zip(("domain", "tunnel_host", "origin"), parts)))
    for spec in a.internal:
        parts = [p.strip() for p in spec.split(",")]
        if len(parts) != 2:
            sys.exit(f"{RED}--internal needs TUNNEL_HOST,ORIGIN (got: {spec}){RESET}")
        services.append({"domain": None, "tunnel_host": parts[0], "origin": parts[1]})
    a.tunnel_host_group = services[0]["tunnel_host"]  # identifies this stack for down() / state filename
    return services


def rebuild_ingress(S):
    cf("PUT", f"/accounts/{ACCT}/cfd_tunnel/{S['tunnel_id']}/configurations", {"config": {"ingress":
        [{"hostname": th, "service": rec["origin"], "originRequest": {"noTLSVerify": True}}
         for th, rec in S["services"].items()] + [{"service": "http_status:404"}]}})


def push_worker_secrets(S, rec, tunnel_host):
    """(Re)pushes one external service's Worker secrets from the current state -- used both at
    initial deploy and whenever header/countries/redirect are changed interactively."""
    slug = rec["domain"].replace(".", "-")
    wrangler("secret", "bulk", cwd=HERE / "workers" / slug, stdin=json.dumps({
        "GATE_NAME": S["header_name"], "GATE_VALUE": S["header_value"], "TUNNEL_HOST": tunnel_host,
        "CF_ACCESS_CLIENT_ID": rec["client_id"], "CF_ACCESS_CLIENT_SECRET": rec["client_secret"],
        "ALLOWED_COUNTRIES": S.get("countries") or "", "REDIRECT_URL": S.get("redirect") or ""}))


def provision_service(S, svc):
    """Idempotent: creates whatever's missing for one service (DNS, Access, Worker-if-external).
    Does NOT rebuild ingress or save beyond its own steps -- caller does both after."""
    domain, tunnel_host, origin = svc["domain"], svc["tunnel_host"], svc["origin"]
    name_slug = (domain or tunnel_host).replace(".", "-")
    rec = S["services"].setdefault(tunnel_host, {})
    # once provisioned, its domain (and so its internal/external kind -- they drive different
    # Access policies) can't be changed in place: `remove` then re-`add` instead
    if rec.get("access_app_id") and rec.get("domain") != domain:
        sys.exit(f"{RED}{tunnel_host} is already provisioned with domain={rec.get('domain')!r}; "
                  f"`remove {tunnel_host}` first to change it{RESET}")
    rec["domain"], rec["origin"] = domain, origin
    S.save()

    if "dns_id" not in rec:
        rec["dns_zone"] = zone_id(tunnel_host)
        rec["dns_id"] = cf("POST", f"/zones/{rec['dns_zone']}/dns_records", {"type": "CNAME", "name": tunnel_host,
                           "content": f"{S['tunnel_id']}.cfargotunnel.com", "proxied": True})["id"]
        S.save()

    if domain and "service_token_id" not in rec:
        st = cf("POST", f"/accounts/{ACCT}/access/service_tokens", {"name": name_slug, "duration": "8760h"})
        # secret is only returned once; kept in the 0600 state file in case the deploy below fails
        rec.update(service_token_id=st["id"], client_id=st["client_id"], client_secret=st["client_secret"])
        S.save()
    if "access_app_id" not in rec:
        rec["access_app_id"] = cf("POST", f"/accounts/{ACCT}/access/apps", {"name": name_slug, "domain": tunnel_host,
                                "type": "self_hosted", "session_duration": "24h"})["id"]
        S.save()
        if not domain and not OWNER_EMAIL:
            sys.exit(f"{RED}OWNER_EMAIL missing: internal services need it in .env (the email allowed through Access){RESET}")
        policy = ({"name": "worker-service-token", "decision": "non_identity",
                   "include": [{"service_token": {"token_id": rec["service_token_id"]}}]} if domain else
                  {"name": "owner-login", "decision": "allow", "include": [{"email": {"email": OWNER_EMAIL}}]})
        cf("POST", f"/accounts/{ACCT}/access/apps/{rec['access_app_id']}/policies", policy)

    if domain:
        # redeployed every time (cheap) so a changed Worker source or a header/geo/redirect
        # edit takes effect on a reused service too, not just on first creation
        wdir = HERE / "workers" / name_slug
        wdir.mkdir(parents=True, exist_ok=True)
        (wdir / "index.js").write_text(WORKER)
        (wdir / "wrangler.jsonc").write_text(json.dumps({"name": name_slug, "main": "index.js",
            "compatibility_date": "2025-01-01", "workers_dev": False,
            "routes": [{"pattern": domain, "custom_domain": True}]}, indent=2))
        rec["worker"] = False
        S.save()  # record before deploying so a half-finished deploy still gets torn down
        wrangler("deploy", cwd=wdir)
        push_worker_secrets(S, rec, tunnel_host)
        rec["worker"] = True
        S.save()


def deprovision_service(S, tunnel_host):
    rec = S["services"].pop(tunnel_host, None)
    if rec is None:
        return False
    if rec.get("domain"):
        slug = rec["domain"].replace(".", "-")
        if "worker" in rec:  # False = deploy may be half done (or never finished); delete anyway
            ensure_wrangler_login()
            r = wrangler("delete", "--name", slug, "--force", check=False, capture=True)
            if r.returncode and "does not exist" not in (r.stdout + r.stderr):
                print(r.stdout, r.stderr)
                sys.exit(f"{RED}wrangler delete failed for {rec['domain']}; fix and retry `remove`{RESET}")
        shutil.rmtree(HERE / "workers" / slug, ignore_errors=True)
    if "access_app_id" in rec:
        cf("DELETE", f"/accounts/{ACCT}/access/apps/{rec['access_app_id']}", soft=True)
    if "service_token_id" in rec:
        cf("DELETE", f"/accounts/{ACCT}/access/service_tokens/{rec['service_token_id']}", soft=True)
    if "dns_id" in rec:
        cf("DELETE", f"/zones/{rec['dns_zone']}/dns_records/{rec['dns_id']}", soft=True)
    S.save()
    return True


HELP = f"""{ORANGE}Commands{RESET}

  {GREEN}list{RESET}
      show current services, each with a ready-to-run test command

  {GREEN}add internal <tunnel_host> <origin>{RESET}
      Access-login-gated only -- no public domain, no Worker
      e.g. add internal admin.internal.example.com http://localhost:9000

  {GREEN}add external <domain> <tunnel_host> <origin>{RESET}
      public domain, gated by the header + Worker
      e.g. add external shop.example.com tun-shop.example.com http://localhost:3000

  {GREEN}remove <domain-or-tunnel_host>{RESET}
      tear down one service, live -- the tunnel stays up
      e.g. remove shop.example.com
      e.g. remove tun-shop.example.com

  {GREEN}header <name> <value>{RESET}
      change the shared gate header on every external Worker
      e.g. header X-NTL-OP s0m3-n3w-s3cr3t

  {GREEN}redirect <url|clear>{RESET}
      change or clear the block-page redirect on every external Worker
      e.g. redirect https://example.com/blocked
      e.g. redirect clear

  {GREEN}countries <CSV|clear>{RESET}
      change or clear the allowed-country list on every external Worker
      e.g. countries US,CA
      e.g. countries clear

  {GREEN}kill{RESET}
      stop the tunnel (then the usual teardown prompt)

  {GREEN}help{RESET}
      this text"""


def test_cmd(S, rec, tunnel_host):
    """A ready-to-run command to test one service."""
    if rec.get("domain"):
        return f"curl https://{rec['domain']}/ -H '{S['header_name']}: {S['header_value']}'"
    return f"curl https://{tunnel_host}/   # blocked without a Cloudflare Access login as {OWNER_EMAIL or 'OWNER_EMAIL'} (browser, or `cloudflared access login {tunnel_host}`)"


def print_list(S):
    if not S["services"]:
        print("  (no services)")
        return
    for th, rec in S["services"].items():
        kind = f"external -> {rec['domain']}" if rec.get("domain") else "internal (Access-login only)"
        print(f"\n  {GREEN}{th}{RESET}  <-  {rec['origin']}  [{kind}]")
        print(f"      test: {test_cmd(S, rec, th)}")


USAGE = {
    "add": "add internal <tunnel_host> <origin>  |  add external <domain> <tunnel_host> <origin>",
    "remove": "remove <domain-or-tunnel_host>",
    "header": "header <name> <value>",
    "redirect": "redirect <url|clear>",
    "countries": "countries <CSV|clear>",
}
HISTFILE = HERE / "state" / ".cfdirector_history"


def push_all_secrets(S):
    for th, rec in S["services"].items():
        if rec.get("domain"):
            push_worker_secrets(S, rec, th)


def interactive_shell(S, p):
    print(f"\n{HELP}\n")
    if readline:
        try:
            HISTFILE.parent.mkdir(exist_ok=True)
            if HISTFILE.exists():
                readline.read_history_file(HISTFILE)
            readline.set_history_length(500)
        except Exception:
            pass  # a corrupt/unreadable history file shouldn't block the shell from starting
    try:
        while True:
            if p.poll() is not None:
                print(f"{RED}[!] cloudflared exited unexpectedly (code {p.returncode}){RESET}")
                return
            try:
                line = input(PROMPT).strip()
            except EOFError:
                print(f"\n{YELLOW}[!] EOF on stdin -- stopping the tunnel{RESET}")
                return
            except KeyboardInterrupt:
                print(f"\n{YELLOW}[!] interrupted -- stopping the tunnel{RESET}")
                return
            if not line:
                continue
            try:
                parts = shlex.split(line)
                verb = parts[0].lower()
                if verb in ("help", "?"):
                    print(HELP)
                elif verb == "list":
                    print_list(S)
                elif verb == "add":
                    kind = parts[1].lower() if len(parts) > 1 else ""
                    if kind == "internal" and len(parts) == 4:
                        th = parts[2]
                        provision_service(S, {"domain": None, "tunnel_host": th, "origin": parts[3]})
                        rebuild_ingress(S)
                        print(f"{GREEN}[+] OK: internal service {th} added{RESET}\n"
                              f"    test: {test_cmd(S, S['services'][th], th)}")
                    elif kind == "external" and len(parts) == 5:
                        d, th, origin = parts[2], parts[3], parts[4]
                        provision_service(S, {"domain": d, "tunnel_host": th, "origin": origin})
                        rebuild_ingress(S)
                        nh = http_status(f"https://{d}/")
                        wh = http_status(f"https://{d}/", {S["header_name"]: S["header_value"]})
                        print(f"{GREEN}[+] OK: external service {d} added{RESET}  "
                              f"(self-test: no header -> {status_color(nh)}, with header -> {status_color(wh)})\n"
                              f"    test: {test_cmd(S, S['services'][th], th)}")
                    else:
                        print(f"{RED}usage: {USAGE['add']}{RESET}")
                elif verb == "remove":
                    if len(parts) != 2:
                        print(f"{RED}usage: {USAGE['remove']}{RESET}")
                    else:
                        key = parts[1]
                        th = key if key in S["services"] else next(
                            (t for t, r in S["services"].items() if r.get("domain") == key), None)
                        if th and deprovision_service(S, th):
                            rebuild_ingress(S)
                            print(f"{GREEN}[+] OK: {key} removed{RESET}")
                        else:
                            print(f"{RED}FAILED: no service matches '{key}' -- see 'list'{RESET}")
                elif verb == "header":
                    if len(parts) != 3:
                        print(f"{RED}usage: {USAGE['header']}{RESET}")
                    else:
                        S["header_name"], S["header_value"] = parts[1], parts[2]
                        S.save()
                        push_all_secrets(S)
                        print(f"{GREEN}[+] OK: header updated on every external service{RESET}")
                elif verb == "redirect":
                    if len(parts) != 2:
                        print(f"{RED}usage: {USAGE['redirect']}{RESET}")
                    else:
                        S["redirect"] = "" if parts[1] == "clear" else parts[1]
                        S.save()
                        push_all_secrets(S)
                        print(f"{GREEN}[+] OK: redirect {'cleared' if not S['redirect'] else 'updated'} "
                              f"on every external service{RESET}")
                elif verb == "countries":
                    if len(parts) != 2:
                        print(f"{RED}usage: {USAGE['countries']}{RESET}")
                    else:
                        S["countries"] = "" if parts[1] == "clear" else parts[1]
                        S.save()
                        push_all_secrets(S)
                        print(f"{GREEN}[+] OK: countries {'cleared' if not S['countries'] else 'updated'} "
                              f"on every external service{RESET}")
                elif verb == "kill":
                    print(f"{YELLOW}[!] stopping the tunnel{RESET}")
                    return
                else:
                    print(f"{RED}FAILED: unknown command '{line}' -- type 'help'{RESET}")
            except SystemExit as e:
                # cf()/wrangler helpers sys.exit(message) on a hard API error -- show it and
                # keep the shell (and tunnel) alive instead of letting it kill the process
                print(f"{RED}FAILED: {e.code}{RESET}")
            except Exception as e:
                print(f"{RED}FAILED: {e}{RESET}")
    finally:
        if readline:
            try:
                # history can contain secrets (e.g. a `header NAME value` command) --
                # same 0600 as the state files, not whatever the umask would otherwise give it
                readline.write_history_file(HISTFILE)
                HISTFILE.chmod(0o600)
            except Exception:
                pass


def up(a):
    services = parse_services(a)
    group_slug = a.tunnel_host_group.replace(".", "-")
    S = State(group_slug)
    hname, _, hval = a.header.partition(":")
    hval = hval.strip()
    if S:
        if S["header_name"] != hname or (hval and hval != S["header_value"]):
            sys.exit(f"{RED}this stack already exists with a different header; run `down {a.tunnel_host_group}` first{RESET}")
        t = cf("GET", f"/accounts/{ACCT}/cfd_tunnel/{S['tunnel_id']}", soft=True) if "tunnel_id" in S else None
        if t is None or t.get("deleted_at"):
            sys.exit(f"{RED}state says a tunnel exists but Cloudflare disagrees; run `down {a.tunnel_host_group}` to clean up{RESET}")
        print(f"{GREEN}[+] existing stack found ({group_slug}), reusing (missing pieces get created){RESET}")
    else:
        S.update(header_name=hname, header_value=hval or secrets.token_urlsafe(32), services={})
    S.setdefault("services", {})
    S["countries"] = a.countries if a.countries is not None else S.get("countries", "")
    S["redirect"] = a.redirect if a.redirect is not None else S.get("redirect", "")

    ensure_wrangler_login()

    if "tunnel_id" not in S:
        S["tunnel_id"] = cf("POST", f"/accounts/{ACCT}/cfd_tunnel", {"name": group_slug, "config_src": "cloudflare"})["id"]
        S.save()

    for svc in services:
        provision_service(S, svc)
    rebuild_ingress(S)

    print(f"\nClient header : {S['header_name']}: {S['header_value']}")
    print_list(S)
    if S["countries"]:
        print(f"Allowed geos  : {S['countries']}")
    if S["redirect"]:
        print(f"On block      : redirect to {S['redirect']}")

    print("\nSelf-test:")
    for svc in services:
        if not svc["domain"]:
            continue
        no_header = http_status(f"https://{svc['domain']}/")
        with_header = http_status(f"https://{svc['domain']}/", {S["header_name"]: S["header_value"]})
        print(f"  {svc['domain']}: no header -> {status_color(no_header)}, with header -> {status_color(with_header)}")
    print()

    def term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, term)
    env = {**os.environ, "TUNNEL_TOKEN": cf("GET", f"/accounts/{ACCT}/cfd_tunnel/{S['tunnel_id']}/token")}
    # cloudflared's own connection-log spam, if left inheriting this terminal, interleaves with
    # (and visually buries) our own "> " prompt -- send it to a file instead, so the prompt
    # shows up cleanly and immediately rather than needing a stray Enter to "reveal" it.
    cf_log = HERE / "state" / f"{group_slug}-cloudflared.log"
    cf_log.parent.mkdir(exist_ok=True)
    with open(cf_log, "a") as lf:
        p = subprocess.Popen(["cloudflared", "tunnel", "--no-autoupdate", "run"], env=env, stdout=lf, stderr=subprocess.STDOUT)
    time.sleep(2)  # let it reach a steady connected-or-not state before we report on it
    if p.poll() is not None:
        print(f"{RED}[!] cloudflared exited immediately (code {p.returncode}) -- see {cf_log}{RESET}")
    else:
        print(f"{GREEN}[+] cloudflared running (pid {p.pid}){RESET}  (logs: {cf_log})")
    try:
        interactive_shell(S, p)
    except KeyboardInterrupt:
        pass
    if p.poll() is None:
        p.terminate()
        p.wait()
    print(f"\n{YELLOW}[!] cloudflared stopped; {group_slug} (and co-hosted services) now down{RESET}")
    if a.teardown or (sys.stdin.isatty() and input("Tear down the infrastructure too? [y/N] ").strip().lower().startswith("y")):
        down(a)  # a.tunnel_host_group was set by parse_services() above
    else:
        print(f"{GREEN}[+] kept. Re-run `up` to reuse it, or `down {a.tunnel_host_group}` to remove it.{RESET}")


def down(a):
    slug = a.tunnel_host_group.replace(".", "-")
    S = State(slug)
    if not S:
        sys.exit(f"{RED}nothing recorded for {a.tunnel_host_group} (no state/{slug}.json){RESET}")
    for tunnel_host in list(S.get("services", {})):
        deprovision_service(S, tunnel_host)
    if "tunnel_id" in S:
        cf("DELETE", f"/accounts/{ACCT}/cfd_tunnel/{S['tunnel_id']}/connections", soft=True)
        cf("DELETE", f"/accounts/{ACCT}/cfd_tunnel/{S['tunnel_id']}", soft=True)
    (HERE / "state" / f"{slug}-cloudflared.log").unlink(missing_ok=True)
    S.path.unlink()
    print(f"{GREEN}[+] {a.tunnel_host_group} torn down{RESET}")


ap = argparse.ArgumentParser()
sub = ap.add_subparsers(dest="cmd", required=True)
u = sub.add_parser("up")
u.add_argument("domain", nargs="?", default=None, help="public Worker custom domain (omit to pick from your zones)")
u.add_argument("tunnel_host", nargs="?", default=None, help="hostname routed to the tunnel, Access-protected (omit to pick from your zones)")
u.add_argument("-H", "--header", required=True, help="NAME or NAME:VALUE the client must send (random value if omitted)")
u.add_argument("-o", "--origin", default=None, help="local service behind the tunnel, for the positional domain/tunnel_host (default http://localhost:80, or prompted if fully interactive)")
u.add_argument("--service", action="append", default=[], metavar="DOMAIN,TUNNEL_HOST,ORIGIN",
               help="add another external service sharing this one tunnel; repeatable")
u.add_argument("--internal", action="append", default=[], metavar="TUNNEL_HOST,ORIGIN",
               help="add an internal-only service (no public domain/Worker, Access-login gated); repeatable")
u.add_argument("--countries", help="comma-separated ISO country codes to allow (e.g. US,CA); unset = no geo restriction")
u.add_argument("--redirect", help="URL to redirect to when blocked (missing/wrong header or disallowed country); unset = 404")
u.add_argument("--teardown", action="store_true", help="tear down on exit without asking (for services/no tty)")
u.set_defaults(fn=up)
d = sub.add_parser("down")
d.add_argument("tunnel_host_group", help="the first service's tunnel_host from the `up` that created this stack")
d.set_defaults(fn=down)
a = ap.parse_args()
a.fn(a)
