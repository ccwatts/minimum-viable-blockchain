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
    def initialize():
        while len(node.Identity.all) < 5:
            node.Identity()

    @staticmethod
    def make_genesis():
        recipient = node.Identity.all.values()[0]  # random.choice(node.Identity.all.items())
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
        # transactions.append(start)
        # inputs:  tx_id, offset
        # outputs: pkh, amount

        # 1/10
        i1 = [(start["NUMBER"], 0)]
        o1 = [[p1, 20], [p2, 5]]
        t1 = TransactionPool.make_transaction(i1, o1)
        transactions.append(t1)

        # 2/10
        i2 = [(t1["NUMBER"], 0)]
        o2 = [(p0, 20)]
        t2 = TransactionPool.make_transaction(i2, o2)
        transactions.append(t2)

        # 3/10
        i3 = [(t1["NUMBER"], 1)]
        o3 = [(p0, 5)]
        t3 = TransactionPool.make_transaction(i3, o3)
        transactions.append(t3)

        # 4/10, merge
        i4 = [(t2["NUMBER"], 0), (t3["NUMBER"], 0)]
        o4 = [(p0, 25)]
        t4 = TransactionPool.make_transaction(i4, o4)
        transactions.append(t4)

        # 5/10
        i5 = [(t4["NUMBER"], 0)]
        o5 = [(p0, 5), (p1, 5), (p2, 5), (p3, 5), (p4, 5)]
        t5 = TransactionPool.make_transaction(i5, o5)
        transactions.append(t5)

        # 6/10, join
        i6 = [(t5["NUMBER"], 0), (t5["NUMBER"], 1), (t5["NUMBER"], 2)]
        o6 = [(p4, 15)]
        t6 = TransactionPool.make_transaction(i6, o6)
        transactions.append(t6)

        # 7/10, another join
        i7 = [(t6["NUMBER"], 0), (t5["NUMBER"], 3), (t5["NUMBER"], 4)]
        o7 = [(p0, 25)]
        t7 = TransactionPool.make_transaction(i7, o7)
        transactions.append(t7)

        # at this point, everything's in t7.
        # 8/10
        i8 = [(t7["NUMBER"], 0)]
        o8 = [(p1, 25)]
        t8 = TransactionPool.make_transaction(i8, o8)
        transactions.append(t8)

        # 9/10
        i9 = [(t8["NUMBER"], 0)]
        o9 = [(p2, 20), (p3, 5)]
        t9 = TransactionPool.make_transaction(i9, o9)
        transactions.append(t9)

        # 10/10
        i10 = [(t9["NUMBER"], 0), (t9["NUMBER"], 1)]
        o10 = [(p1, 25)]
        t10 = TransactionPool.make_transaction(i10, o10)
        transactions.append(t10)

        # 11/10 invalid -- trying to spend more than you have
        i_inv = [(t9["NUMBER"], 1)]
        o_inv = [(p3, 100)]
        t_inv = TransactionPool.make_transaction(i_inv, o_inv)
        transactions.append(t_inv)

        # 12/10 malicious -- double spend
        i_mal = [(t9["NUMBER"], 0)]
        o_mal = [(p4, 20)]
        t_mal = TransactionPool.make_transaction(i_mal, o_mal)
        transactions.append(t_mal)

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

