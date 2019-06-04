import json
import random
from collections import OrderedDict
from Crypto.Hash import SHA256
import node


def sha256(string):
    return SHA256.new(string).hexdigest()


class TransactionPool:
    all = dict()
    def __init__(self):
        # get all the identities we need
        while len(node.Identity.all) < 5:
            node.Identity()

    @staticmethod
    def make_genesis():
        recipient = node.Identity.all.values()[0] #random.choice(node.Identity.all.items())
        output = [(recipient.pkh, node.Node.GENESIS_AMOUNT)]
        return TransactionPool.make_transaction(list(), output), recipient

    @staticmethod
    def get_output(input_pair):
        tx_id = input_pair[0]
        offset = input_pair[1]
        return TransactionPool.all[tx_id]["OUTPUT"][offset]

    @staticmethod
    def get_sig_content(input_pair, output):
        return str(json.dumps(input_pair) + json.dumps(output))

    @staticmethod
    def get_id_content(inputs, outputs, sigs):
        return str(json.dumps(inputs) + json.dumps(outputs) + json.dumps(sigs))

    @staticmethod
    def generate_io_chain():
        # need at LEAST 10.
        participants = node.Identity.all.values()
        p0 = participants[0].pkh
        p1 = participants[1].pkh
        p2 = participants[2].pkh
        p3 = participants[3].pkh
        p4 = participants[4].pkh

        transactions = list()
        start, recipient = TransactionPool.make_genesis()
        #transactions.append(start)
        # inputs:  tx_id, offset
        # outputs: pkh, amount
        i1 = [(start["NUMBER"], 0)]
        o1 = [[p1, 20], [p2, 5]]
        t1 = TransactionPool.make_transaction(i1, o1)
        #t1["OUTPUT"][0][1] = 25
        transactions.append(t1)

        with open("transactions.json", "w") as f:
            f.write(json.dumps(transactions))

        return start, transactions

    @staticmethod
    def make_transaction(inputs, outputs):
        data = OrderedDict()
        data["INPUT"] = inputs
        data["OUTPUT"] = outputs
        # what we do ourselves.
        # make the signatures once the inputs/outputs are known
        sigstrings = list()
        first_signer = None
        if len(inputs) == 1:
            type = "TRANS"
        else:
            # assume merge, we'll change over later when we parse input if need be
            type = "MERGE"

        for pair in data["INPUT"]:
            content = TransactionPool.get_sig_content(pair, outputs)
            output_source = TransactionPool.get_output(pair)
            signer = node.Identity.all[output_source[0]]
            if first_signer is None:
                first_signer = signer
            elif first_signer != signer:
                type = "JOIN"
            signature = signer.sign(content)
            sigstrings.append(signature)

        data["TYPE"] = type

        data["SIGNATURE"] = [sha256(type), sigstrings]

        # hash everything to get the identifier
        id_target = TransactionPool.get_id_content(inputs, outputs, sigstrings)
        identifier = sha256(json.dumps(id_target))
        data["NUMBER"] = identifier
        TransactionPool.all[identifier] = data
        print json.dumps(data)
        return data