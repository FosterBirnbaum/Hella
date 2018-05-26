import sys, os
sys.path.append(os.path.expandvars('../monitor'))
from test_data import Data_point, Test_data
import argparse
import pickle

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--train_file', help='the .pkl file to read packets from')
    parser.add_argument('--test_file', help='the .pkl file to write to')
    args = parser.parse_args()

    with open(args.train_file, 'rb') as r:
    	packets = pickle.load(r)

    wrapped_packets = Test_data([Data_point(pkt, malicious=False) for pkt in r])

    with open(args.test_file, 'wb') as w:
    	pickle.dump(wrapped_packets, w)