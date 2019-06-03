# aaaaa
from node import *

NUM_NODES = 2


def initialize():
    for i in xrange(NUM_NODES):
        n = Node()
    cbtx = make_genesis()
    for _, v in Node.nodes.items():
        v.accept_genesis(cbtx)
    return cbtx


def make_genesis():
    data = dict()
    chosen_node = random.choice(Node.nodes.keys())
    data["inputs"] = list()
    data["outputs"] = [(chosen_node, Node.GENESIS_AMOUNT)]
    data["prev"] = None
    data["sigstrings"] = list()
    data["id"] = sha256(json.dumps(data))
    return data


if __name__ == "__main__":
    cbtx = initialize()
    sender = Node.nodes[cbtx["outputs"][0][0]]
    recipient = random.choice(Node.nodes.values())
    
    inputs = [(cbtx["id"], 0)]
    outputs = [(Node.GENESIS_AMOUNT, sender.pkh)]

    sent = sender.make_transaction(inputs, outputs, cbtx)
    sender.mine(sent)
    # print sender == recipient
    # print sent
    # sender.add_tx(sent)
    print sender.validate(sent)
    print sender.verify(sent)
    exit()



