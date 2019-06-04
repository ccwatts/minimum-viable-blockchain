# aaaaa
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
    transactions.TransactionPool.all[data["NUMBER"]] = data
    return data

# https://pymotw.com/2/threading/ used as thread reference
'''
def consumer(cond):
    """wait for the condition and use the resource"""
    lg.debug('Starting consumer thread')
    t = thr.currentThread()
    with cond:
        cond.wait()
        lg.debug('Resource is available to consumer')

def producer(cond):
    """set up the resource to be used by the consumer"""
    lg.debug('Starting producer thread')
    with cond:
        lg.debug('Making resource available')
        cond.notifyAll()

# main        
    condition = thr.Condition()
    c1 = thr.Thread(name='c1', target=consumer, args=(condition,))
    c2 = thr.Thread(name='c2', target=consumer, args=(condition,))
    p = thr.Thread(name='p', target=producer, args=(condition,))

    c1.start()
    time.sleep(2)
    c2.start()
    time.sleep(2)
    p.start()
    '''

def utp_monitor(utp, cond):
    lg.debug('Starting utp thread')
    with cond:
        lg.debug('Making resource available')
        cond.notifyAll()

def node_thread(bnode, utp, cond):
    lg.debug('Starting node thread')
    with cond:
        print bnode
        cond.wait()
        lg.debug('Resource is available to consumer')
        print utp
        bnode.loop(utp)


if __name__ == "__main__":
    lg.basicConfig(level=lg.DEBUG, format='%(asctime)s (%(threadName)-2s) %(message)s',)
    condition = thr.Condition()

    transactions.TransactionPool.initialize()
    genesis, utp = transactions.TransactionPool.generate_io_chain()

    threads = [None] * 10

    utpt = thr.Thread(name='ut', target=utp_monitor, args=(utp, condition,))

    for i in xrange(10):
        temp = node.Node()
        temp.accept_genesis(genesis)
        tname = "t%s" % (i)
        threads[i] = thr.Thread(name=tname, target=node_thread, args=(temp, utp, condition,))

    '''
    n = node.Node()
    n.accept_genesis(genesis)
    n.loop(utp)


    for vn in node.Node.all.values():
        vn.print_chain()
        print
    exit()
    '''

    for i in xrange(10):
        threads[i].start()
    utpt.start()

    '''
    for i in range(NUM_IDENS):
        iden = node.Identity()
    cbtx = initialize()
    sender = node.Identity.all[cbtx["OUTPUT"][0][0]]
    recipient = random.choice(node.Identity.all.values())
    verifier = random.choice(node.Node.all.values())
    inputs = [(cbtx["NUMBER"], 0)]
    outputs = [(node.Node.GENESIS_AMOUNT, sender.pkh)]
    sent = transactions.TransactionPool.make_transaction(inputs, outputs)
    verifier.mine(sent)
    # print sender == recipient
    # print sent
    # sender.add_tx(sent)
    print verifier.validate(sent)
    print verifier.verify(sent)
    exit()
    '''



