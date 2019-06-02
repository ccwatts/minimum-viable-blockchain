# aaaaa
from node import *

# there is probably a better way to do this.
hash_bound = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
coinbase_amount = 25

NUM_NODES = 1

def verify_hash(in_hash):
    global hash_bound
    numerical_value = int(in_hash, 16)
    return numerical_value < hash_bound


def initialize():
    for i in xrange(NUM_NODES):
        n = Node()
    cbtx = make_coinbase()

    for _, v in Node.nodes.items():
        v.accept_coinbase(cbtx)

def make_coinbase():
    data = dict()
    chosen_node = random.choice(Node.nodes.keys())
    data["input"] = list()
    data["output"] = (chosen_node, coinbase_amount)
    data["prev"] = None
    data["sigstrings"] = list()
    data["id"] = sha256(json.dumps(data))
    return data


if __name__ == "__main__":
    '''
    n = Node()
    n2 = Node()
    print n.pkh
    print n2.pkh
    print(make_coinbase())
    '''
    initialize()
    for _, n in Node.nodes.items():
        print n.chain
    exit()
    data = {"hello": "world"}
    nonce = Node().proof_of_work(data)
    print nonce
    pass



