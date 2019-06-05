import node
import transactions
import random
import json
import threading as thr
import logging as lg
import time

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
    transactions.TransactionGen.all[data["NUMBER"]] = data
    return data

if __name__ == "__main__":
    nodes = list()
    genesis, pool = transactions.TransactionGen.generate_io_chain()
    for i in range(10):
        n = node.Node(genesis, pool)
        nodes.append(n)

    #nodes[0].loop()
    for n in nodes:
        n.start()

    #for n in nodes:
    #    n.print_chain()

    '''
    utpt = thr.Thread(name='ut', target=utp_monitor, args=(utp, condition,))

    for i in xrange(10):
        temp = node.Node()
        temp.accept_genesis(genesis)
        tname = "t%s" % (i)
        threads[i] = thr.Thread(name=tname, target=node_thread, args=(temp, utp, condition,))

    for i in xrange(10):
        threads[i].start()
    utpt.start()
    '''

    '''
    for i in range(NUM_IDENS):
        iden = node.Identity()
    cbtx = initialize()
    sender = node.Identity.all[cbtx["OUTPUT"][0][0]]
    recipient = random.choice(node.Identity.all.values())
    verifier = random.choice(node.Node.all.values())
    inputs = [(cbtx["NUMBER"], 0)]
    outputs = [(node.Node.GENESIS_AMOUNT, sender.pkh)]
    sent = transactions.TransactionGen.make_transaction(inputs, outputs)
    verifier.mine(sent)
    # print sender == recipient
    # print sent
    # sender.add_tx(sent)
    print verifier.validate(sent)
    print verifier.verify(sent)
    exit()
    '''



