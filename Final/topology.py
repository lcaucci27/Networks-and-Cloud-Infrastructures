from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host, RemoteController
from mininet.link import TCLink
import sys

def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

class Environment(object):
    def __init__(self):
        self.net = Mininet(controller=RemoteController, link=TCLink)

        info(color_text("*** Starting controller ***\n", '34'))
        self.controller = self.net.addController('c1', controller=RemoteController)
        self.controller.start()

        info(color_text("*** Adding hosts ***\n", '32'))
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')

        info(color_text("*** Adding switches ***\n", '36'))
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)

        info(color_text("*** Adding links between hosts and switches ***\n", '35'))
        self.net.addLink(self.h1, self.s1, bw=10)
        self.net.addLink(self.h2, self.s2, bw=10)
        self.net.addLink(self.h3, self.s3, bw=10)
        self.net.addLink(self.h4, self.s1, bw=10)

        info(color_text("*** Adding links between switches ***\n", '33'))
        # small max_queue_size on the inter-switch links so congestion shows up quickly during the DoS simulation
        self.net.addLink(self.s4, self.s1, bw=10, max_queue_size=500)
        self.net.addLink(self.s4, self.s2, bw=10, max_queue_size=500)
        self.net.addLink(self.s4, self.s3, bw=10, max_queue_size=500)

        info(color_text("*** Starting network ***\n", '34'))
        self.net.build()
        self.net.start()

if __name__ == '__main__':
    setLogLevel('info')

    info(color_text('=== Starting the environment ===\n', '31'))
    env = Environment()

    info(color_text("*** Running CLI ***\n", '32'))
    CLI(env.net)
