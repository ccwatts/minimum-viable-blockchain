# aaaaa
import node
import transactions
import random
import json

NUM_NODES = 2
NUM_IDENS = 5

def initialize():
    for i in xrange(NUM_NODES):
        node.Node()
    cbtx = make_genesis()
    for _, v in node.Node.all.items():
        v.accept_genesis(cbtx)
    return cbtx


def make_genesis():
    data = dict()
    chosen_node = random.choice(node.Identity.all.keys())
    data["INPUT"] = list()
    data["OUTPUT"] = [(chosen_node, node.Node.GENESIS_AMOUNT)]
    data["PREV"] = None
    data["SIGNATURE"] = list()
    data["NUMBER"] = node.sha256(json.dumps(data))
    transactions.TransactionPool.all[data["NUMBER"]] = data
    return data


if __name__ == "__main__":
    transactions.TransactionPool.initialize()
    genesis, utp = transactions.TransactionPool.generate_io_chain()

    for i in xrange(10):
        temp = node.Node()
        temp.accept_genesis(genesis)

    n = node.Node()
    n.accept_genesis(genesis)
    n.loop(utp)

    for vn in node.Node.all.values():
        vn.print_chain()
        print



