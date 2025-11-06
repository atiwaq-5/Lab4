#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import Host
from mininet.link import TCLink
from mininet.cli import CLI

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
    print('*** Ready. Run:\n    source mn_quickcheck_v6.cli\n'
          'or: source mn_run_tests4.cli\n')

    CLI(net)
    net.stop()
