from scapy.all import *

from headers import Seer
from anomaly_model import AnomalyModel
from utils import *
import cPickle as pickle

ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'

# TODO: update with actual ethernet address of ECU
ETH_SRC = ETH_BROADCAST

class Method():
    def __init__(self, send_fn=sendp):
        self.model = AnomalyModel()
        self.load_model()
        self.send_fn = send_fn

    def load_model(self):
        
        try:
            self.model.load('model.pkl')
        except:
            try:
                packets = pickle.load(open('packets.pkl', 'rb'))
                print("Loaded packets")
                print(packets[:5])
            except:
                print("Starting reading")
                reader = read_tcpdump_file('data/outside.tcpdump')
                print("Done reading")
                packets = featurize_scapy_pkts(dpkt_to_scapy(reader))
                print("Done featurizing")
                pickle.dump(packets, open('packets.pkl', 'wb'))
            self.model.fit(packets)
            self.model.save('model.pkl')

    def handle_pkt(self, pkt):
        featurized_pkt = featurize_scapy_pkt(pkt)
        prediction = self.model.predict(featurized_pkt)
        ether = Ether(dst=ETH_BROADCAST, src=ETH_SRC)
        seer = Seer(malicious=prediction, data=pkt)
        self.send_fn(ether / seer)

    def run(self):
        sniff(prn=self.handle_pkt, count=0)
