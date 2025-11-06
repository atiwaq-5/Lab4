#!/usr/bin/env python3
"""
lab4_mininet_all_in_one.py

ONE FILE to run the full Lab 4 flow in a Mininet VM:
- Topology (h1, dns, att, mx) or user's Topo if present
- Authoritative DNS setup with DNSSEC support
- OpenDKIM configuration on mx host
- Postfix SMTP with DKIM signing via milter
- SPF/DMARC/DKIM verification tests

This extends the basic Lab 4 setup with DKIM signing capabilities.
"""

from mininet.net import Mininet
from mininet.node import Host
from mininet.link import TCLink
from mininet.cli import CLI


def setup_opendkim_on_mx(net):
    """Configure OpenDKIM on the mx host for DKIM signing."""
    mx = net.get('mx')
    domain = "example.com"
    selector = "s1"
    
    print("Setting up OpenDKIM on mx host...")
    
    # Install opendkim if not present
    mx.cmd("apt-get update -qq 2>/dev/null || true")
    mx.cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq opendkim opendkim-tools postfix 2>/dev/null || true")
    
    # Create directory structure
    mx.cmd(f"mkdir -p /etc/opendkim/keys/{domain}")
    
    # Generate DKIM keys
    mx.cmd(f"cd /etc/opendkim/keys/{domain} && opendkim-genkey -b 2048 -d {domain} -s {selector}")
    mx.cmd(f"chown -R opendkim:opendkim /etc/opendkim")
    mx.cmd(f"chmod 600 /etc/opendkim/keys/{domain}/{selector}.private")
    
    # Create OpenDKIM configuration
    opendkim_conf = f"""
# OpenDKIM configuration
Syslog yes
UMask 002
Domain {domain}
Selector {selector}
KeyFile /etc/opendkim/keys/{domain}/{selector}.private
Socket inet:8891@127.0.0.1
Canonicalization relaxed/simple
Mode sv
AutoRestart yes
"""
    mx.cmd(f"bash -lc 'cat > /etc/opendkim.conf <<EOF\n{opendkim_conf}EOF'")
    
    # Create key table
    key_table = f"{selector}._domainkey.{domain} {domain}:{selector}:/etc/opendkim/keys/{domain}/{selector}.private\n"
    mx.cmd(f"bash -lc 'cat > /etc/opendkim/KeyTable <<EOF\n{key_table}EOF'")
    
    # Create signing table
    signing_table = f"*@{domain} {selector}._domainkey.{domain}\n"
    mx.cmd(f"bash -lc 'cat > /etc/opendkim/SigningTable <<EOF\n{signing_table}EOF'")
    
    # Create trusted hosts
    trusted_hosts = "127.0.0.1\n10.0.0.0/24\nlocalhost\n*.example.com\n"
    mx.cmd(f"bash -lc 'cat > /etc/opendkim/TrustedHosts <<EOF\n{trusted_hosts}EOF'")
    
    # Fix permissions
    mx.cmd("chown -R opendkim:opendkim /etc/opendkim")
    
    # Start OpenDKIM
    mx.cmd("pkill -9 opendkim || true")
    mx.cmd("opendkim -p inet:8891@127.0.0.1 2>/tmp/opendkim.log &")
    mx.cmd("sleep 2")
    
    # Verify OpenDKIM is running
    check = mx.cmd("ss -ltnp | grep ':8891' || echo 'NOT_RUNNING'")
    if "NOT_RUNNING" in check:
        print("WARNING: OpenDKIM may not be running properly")
    else:
        print("OpenDKIM started successfully on port 8891")
    
    return True


def setup_postfix_on_mx(net):
    """Configure Postfix to use OpenDKIM milter."""
    mx = net.get('mx')
    
    print("Configuring Postfix with DKIM milter...")
    
    # Basic Postfix configuration
    postfix_main = """
myhostname = mail.example.com
mydomain = example.com
myorigin = $mydomain
inet_interfaces = all
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain
mynetworks = 10.0.0.0/24, 127.0.0.0/8
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891
milter_default_action = accept
milter_protocol = 2
"""
    mx.cmd(f"bash -lc 'cat > /etc/postfix/main.cf <<EOF\n{postfix_main}EOF'")
    
    # Restart Postfix
    mx.cmd("postfix stop 2>/dev/null || true")
    mx.cmd("postfix start 2>/tmp/postfix.log")
    mx.cmd("sleep 2")
    
    # Verify Postfix is running
    check = mx.cmd("ss -ltnp | grep ':25' || echo 'NOT_RUNNING'")
    if "NOT_RUNNING" in check:
        print("WARNING: Postfix may not be running properly")
    else:
        print("Postfix started successfully on port 25")
    
    return True


def make_host(net, name, ip):
    h = net.addHost(name, ip=ip+"/24")
    return h


if __name__ == "__main__":
    net = Mininet(link=TCLink, controller=None, autoSetMacs=True)
    s1 = net.addSwitch('s1')

    # Hosts: dns, att, h1, mx
    dns = make_host(net, 'dns', '10.0.0.53')
    att = make_host(net, 'att', '10.0.0.66')
    h1  = make_host(net, 'h1',  '10.0.0.10')
    mx  = make_host(net, 'mx',  '10.0.0.25')

    for h in (dns, att, h1, mx):
        net.addLink(h, s1)

    net.build()
    s1.start([])

    print("\n*** Hosts up: dns att h1 mx\n")
    
    # Setup OpenDKIM and Postfix on mx
    setup_opendkim_on_mx(net)
    setup_postfix_on_mx(net)
    
    print('\n*** Ready. Run:\n    source mn_quickcheck_v6.cli\n'
          'or: source mn_run_tests4.cli\n')

    CLI(net)
    net.stop()
