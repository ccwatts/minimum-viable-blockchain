# aaaaa
from transactions import *
from node import *

NUM_NODES = 2
NUM_IDENS = 5

def initialize():
    for i in xrange(NUM_NODES):
        Node()
    cbtx = make_genesis()
    for _, v in Node.all.items():
        v.accept_genesis(cbtx)
    return cbtx


def make_genesis():
    data = dict()
    chosen_node = random.choice(Identity.all.keys())
    data["INPUT"] = list()
    data["OUTPUT"] = [(chosen_node, Node.GENESIS_AMOUNT)]
    data["PREV"] = None
    data["SIGNATURE"] = list()
    data["NUMBER"] = sha256(json.dumps(data))
    Transactions.all[data["NUMBER"]] = data
    return data


if __name__ == "__main__":
    for i in range(NUM_IDENS):
        iden = Identity()
    cbtx = initialize()
    sender = Identity.all[cbtx["OUTPUT"][0][0]]
    recipient = random.choice(Identity.all.values())
    verifier = random.choice(Node.all.values())

    inputs = [(cbtx["NUMBER"], 0)]
    outputs = [(Node.GENESIS_AMOUNT, sender.pkh)]

    sent = iden.make_transaction(inputs, outputs, cbtx)
    verifier.mine(sent)
    # print sender == recipient
    # print sent
    # sender.add_tx(sent)
    print verifier.validate(sent)
    print verifier.verify(sent)
    exit()



