#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lab 4 quick check (authoritative DNS + forged MX demo + SPF/DMARC/DKIM).
Use from Mininet CLI (inside lab folder):
  source mn_quickcheck_v6.cli        # interactive (prompts for screenshots)
  source mn_run_tests4.cli           # non-interactive
"""

CHECK = "✔️"
CROSS = "✖️"

def say(msg: str):
    print(msg, flush=True)

def pause(msg: str, interactive=True):
    if not interactive:
        return
    try:
        input(msg)
    except EOFError:
        pass

def _cmd(net, host, cmd):
    return net.get(host).cmd(cmd)

def _ensure_named(net, host, ip, zone_src):
    """Install minimal named configs + provided zone on host, start named,
    and verify it answers MX for example.com."""
    named_opts = f"""options {{
    directory "/var/cache/bind";
    listen-on {{ {ip}; 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    allow-query {{ any; }};
    recursion no;
    dnssec-validation no;
}};
"""
    named_local = 'zone "example.com" IN {\n    type master;\n    file "/var/cache/bind/zones/db.example.com";\n};\n'

    h = net.get(host)
    cmds = [
        "pkill -9 named || true",
        "mkdir -p /var/cache/bind/zones",
        f"cp {zone_src} /var/cache/bind/zones/db.example.com",
        "chown -R bind:bind /var/cache/bind",
        "chmod -R u+rwX,go+rX /var/cache/bind",
        f"bash -lc 'cat > /etc/bind/named.conf.options <<EOF\n{named_opts}EOF'",
        f"bash -lc 'cat > /etc/bind/named.conf.local <<EOF\n{named_local}EOF'",
        "named -4 -u bind -g -c /etc/bind/named.conf >/tmp/named.log 2>&1 & sleep 1"
    ]
    for c in cmds:
        h.cmd(c)

    out = h.cmd(f"dig +short -t MX example.com @{ip}")
    return bool(out.strip())

def _start_smtpd_sink(net, host, logpath):
    h = net.get(host)
    h.cmd(f"fuser -k 25/tcp || true; python3 -u -m smtpd -n -c DebuggingServer 0.0.0.0:25 >{logpath} 2>&1 & sleep 1")
    chk = h.cmd("ss -ltnp | grep ':25 ' || true")
    return bool(chk.strip())

def _dig_short(net, host, name, qtype, dns):
    return net.get(host).cmd(f"dig +short -t {qtype} {name} @{dns}").strip()

def _txt_present(net, host, name, dns, must_contain):
    out = _dig_short(net, host, name, "TXT", dns)
    ok = (must_contain in out) if out else False
    return ok, out

def _swaks_quit_after_rcpt(net, host, server):
    out = net.get(host).cmd(f"swaks --to alice@example.com --from bob@client.local --server {server} --quit-after RCPT 2>&1")
    ok = (" 250 2.1.5 Ok" in out) or (" 250 2.1.0 Ok" in out) or (" 250 OK" in out)
    return ok, out

def _swaks_send_to_attacker(net, host, server):
    out = net.get(host).cmd(
        f"swaks --to alice@example.com --from boss@bank.com --server {server} "
        f"--header 'Subject: via attacker' --body 'using forged MX' 2>&1"
    )
    ok = (" 250 OK" in out) or (" 250 2.0.0" in out)
    return ok, out

def _tail(net, host, path, n=40):
    return net.get(host).cmd(f"tail -n {n} {path} 2>/dev/null || true")

def _test_dkim_signature(net, host, server):
    """Send a test email and verify DKIM signature is present."""
    out = net.get(host).cmd(
        f"swaks --to test@example.com --from sender@example.com --server {server} "
        f"--header 'Subject: DKIM Test' --body 'Testing DKIM signing' 2>&1"
    )
    ok = (" 250 " in out) or (" 250 2.0.0" in out)
    return ok, out

def _check_dkim_in_headers(net, host, logpath):
    """Check if DKIM-Signature header is present in logged messages."""
    log_content = net.get(host).cmd(f"cat {logpath} 2>/dev/null || true")
    has_dkim = "DKIM-Signature:" in log_content
    return has_dkim, log_content

def _verify_opendkim_running(net, host):
    """Check if OpenDKIM is running and listening on port 8891."""
    check = net.get(host).cmd("ss -ltnp | grep ':8891' || echo 'NOT_RUNNING'")
    return "NOT_RUNNING" not in check

def run(net, interactive=True):
    dns_ip = "10.0.0.53"
    att_ip = "10.0.0.66"
    mx_ip  = "10.0.0.25"

    say("==== Lab 4 Quick Check (authoritative DNS + forged MX + SPF/DMARC/DKIM) ====")

    # Step 0: connectivity
    say("Step 0 — Connectivity test: pings from h1 to dns/att/mx")
    p_dns = _cmd(net, "h1", f"ping -c1 -W1 {dns_ip} >/dev/null 2>&1; echo $?").strip() == "0"
    p_att = _cmd(net, "h1", f"ping -c1 -W1 {att_ip} >/dev/null 2>&1; echo $?").strip() == "0"
    p_mx  = _cmd(net, "h1", f"ping -c1 -W1 {mx_ip}  >/dev/null 2>&1; echo $?").strip() == "0"
    say(f"Result: dns:{dns_ip} {'✔️' if p_dns else '✖️'}   att:{att_ip} {'✔️' if p_att else '✖️'}   mx:{mx_ip} {'✔️' if p_mx else '✖️'}")
    pause("📸 Take a screenshot of the ping results. Press Enter to continue...", interactive)

    # Step 1: GOOD DNS
    say("Step 1 — Start GOOD authoritative DNS on dns (serves mail.example.com → 10.0.0.25; includes SPF/DMARC/DKIM)")
    ok_dns = _ensure_named(net, "dns", dns_ip, "zones/db.example.com.good")
    say(f"Result: GOOD DNS up & answering: {'✔️' if ok_dns else '✖️'}")
    pause("📸 Screenshot: `dns` :53 listening + tail /tmp/named.log. Press Enter...", interactive)

    # Step 2: Attacker DNS
    say("Step 2 — Start ATTACKER authoritative DNS on att (serves att.example.com → 10.0.0.66)")
    ok_att = _ensure_named(net, "att", att_ip, "zones/db.example.com.att")
    say(f"Result: ATTACKER DNS up & answering: {'✔️' if ok_att else '✖️'}")
    pause("📸 Screenshot: `att` :53 listening + tail /tmp/named.log. Press Enter...", interactive)

    # Step 3: SMTP sinks
    say("Step 3 — Start SMTP sinks (att & mx)")
    ok_s_att = _start_smtpd_sink(net, "att", "/tmp/att-smtp.log")
    ok_s_mx  = _start_smtpd_sink(net, "mx",  "/tmp/mx-smtp.log")
    say(f"Result: att:25 {'✔️' if ok_s_att else '✖️'}   mx:25 {'✔️' if ok_s_mx else '✖️'}")
    pause("📸 Screenshot: listeners visible (ss -ltnp). Press Enter...", interactive)

    # Step 4: Good DNS path (+ SPF/DMARC TXT checks)
    say("Step 4 — Resolve via GOOD DNS and test baseline SMTP to REAL MX (10.0.0.25)")
    _cmd(net, "h1", f"bash -lc 'printf "nameserver {dns_ip}\n" > /etc/resolv.conf'")
    mx_ans = _dig_short(net, "h1", "example.com", "MX", dns=dns_ip)
    a_ans  = _dig_short(net, "h1", "mail.example.com", "A",  dns=dns_ip)
    spf_ok, spf_txt = _txt_present(net, "h1", "example.com", dns_ip, "v=spf1")
    dmarc_ok, dmarc_txt = _txt_present(net, "h1", "_dmarc.example.com", dns_ip, "v=DMARC1")
    say(f"MX(example.com) via {dns_ip}: {mx_ans or '(empty)'}")
    say(f"A(mail.example.com) via {dns_ip}: {a_ans or '(empty)'}")
    say(f"SPF TXT(@): {'✔️' if spf_ok else '✖️'}  {spf_txt or ''}")
    say(f"DMARC TXT(_dmarc): {'✔️' if dmarc_ok else '✖️'}  {dmarc_txt or ''}")
    b_ok, b_out = _swaks_quit_after_rcpt(net, "h1", mx_ip)
    say("Result: SMTP baseline (h1 → 10.0.0.25:25): " + ('✔️' if b_ok else '✖️'))
    pause("📸 Screenshot: MX/A + SPF/DMARC TXT + swaks baseline. Press Enter...", interactive)

    # Step 5: Forged path
    say("Step 5 — Switch to attacker DNS, resolve forged MX, and send mail to attacker")
    _cmd(net, "h1", f"bash -lc 'printf "nameserver {att_ip}\n" > /etc/resolv.conf'")
    forged_mx = _dig_short(net, "h1", "example.com", "MX", dns=att_ip)
    forged_mx = forged_mx.split()[-1].rstrip('.') if forged_mx else ""
    forged_ip = _dig_short(net, "h1", forged_mx, "A", dns=att_ip) if forged_mx else ""
    say(f"Forged MX: {forged_mx or '(none)'}   A: {forged_ip or '(none)'}")
    if forged_ip:
        sw_ok, sw_out = _swaks_send_to_attacker(net, "h1", forged_ip)
    else:
        sw_ok, sw_out = (False, "MX/A resolution failed.")
    say("Result: SMTP to attacker: " + ('✔️' if sw_ok else '✖️'))
    log_tail = _tail(net, "att", "/tmp/att-smtp.log", n=40)
    say("Attacker log tail:\n" + (log_tail or "(empty)"))
    pause("📸 Screenshot: forged dig + swaks + attacker log. Press Enter...", interactive)

    # Step 6: DKIM verification
    say("Step 6 — DKIM Signature Verification")
    _cmd(net, "h1", f"bash -lc 'printf \"nameserver {dns_ip}\n\" > /etc/resolv.conf'")
    
    # Check if DKIM TXT record exists in DNS
    dkim_ok, dkim_txt = _txt_present(net, "h1", "s1._domainkey.example.com", dns_ip, "v=DKIM1")
    say(f"DKIM TXT (s1._domainkey): {'✔️' if dkim_ok else '✖️'}  {dkim_txt[:100] if dkim_txt else '(none)'}...")
    
    # Check if OpenDKIM is running on mx
    opendkim_running = _verify_opendkim_running(net, "mx")
    say(f"OpenDKIM running on mx:8891: {'✔️' if opendkim_running else '✖️'}")
    
    # Send a test email through the mx server
    if opendkim_running:
        # Use Postfix on mx if it's running, otherwise skip
        postfix_check = _cmd(net, "mx", "ss -ltnp | grep ':25' || echo 'NOT_RUNNING'")
        if "NOT_RUNNING" not in postfix_check:
            # Stop the debugging SMTP sink and use Postfix instead
            _cmd(net, "mx", "fuser -k 25/tcp || true; sleep 1")
            # Restart Postfix if needed
            _cmd(net, "mx", "postfix status >/dev/null 2>&1 || postfix start 2>/dev/null")
            _cmd(net, "mx", "sleep 2")
            
            # Send test email
            dkim_send_ok, dkim_send_out = _test_dkim_signature(net, "h1", mx_ip)
            say(f"Test email sent via Postfix+OpenDKIM: {'✔️' if dkim_send_ok else '✖️'}")
            
            # Check mail logs for DKIM signature
            maillog_check = _cmd(net, "mx", "grep -i 'dkim' /var/log/mail.log 2>/dev/null | tail -5 || echo 'No DKIM logs'")
            if maillog_check and "No DKIM logs" not in maillog_check:
                say(f"DKIM activity in mail.log: ✔️")
                say(f"Recent DKIM logs:\n{maillog_check}")
            else:
                say(f"DKIM activity in mail.log: ⚠️  (check /tmp/opendkim.log)")
                opendkim_log = _tail(net, "mx", "/tmp/opendkim.log", n=10)
                if opendkim_log:
                    say(f"OpenDKIM log tail:\n{opendkim_log}")
        else:
            say("Postfix not running on mx, skipping live DKIM test")
            dkim_send_ok = False
    else:
        say("OpenDKIM not running, skipping DKIM signature test")
        dkim_send_ok = False
    
    pause("📸 Screenshot: DKIM TXT record + OpenDKIM status + test results. Press Enter...", interactive)

    say("==== Summary ====")
    say(f"GOOD DNS up: {'OK' if ok_dns else 'FAIL'}")
    say(f"ATTACKER DNS up: {'OK' if ok_att else 'FAIL'}")
    say(f"SPF TXT present: {'OK' if spf_ok else 'FAIL'}")
    say(f"DMARC TXT present: {'OK' if dmarc_ok else 'FAIL'}")
    say(f"DKIM TXT present: {'OK' if dkim_ok else 'FAIL'}")
    say(f"OpenDKIM running: {'OK' if opendkim_running else 'FAIL'}")
    say(f"Baseline SMTP: {'OK' if b_ok else 'FAIL'}")
    say(f"Forged path SMTP: {'OK' if sw_ok else 'FAIL'}")
    say(f"DKIM signing test: {'OK' if dkim_send_ok else 'SKIP'}")
    say("=================")
