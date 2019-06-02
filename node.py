import json
import random
from ecdsa import SigningKey
from Crypto.Hash import SHA256

def sha256(string):
    return SHA256.new(string).hexdigest()

class Node:
    nodes = dict()
    def __init__(self):
        # placeholders
        self.sk = SigningKey.generate()
        self.pk = self.sk.get_verifying_key()
        self.pkh = sha256(self.pk.to_string())
        self.chain = None
        Node.nodes[self.pkh] = self

    def accept_coinbase(self, coinbase_tx):
        self.chain = dict()
        self.chain[coinbase_tx["id"]] = coinbase_tx

    def make_transaction(self, inputs, output, prev):  # , nonce, powork):
        data = dict()
        # List of (ID hash, Offset) pairs
        data["input"] = inputs
        # List of (ID hash, Amount) pairs
        data["output"] = output
        # A singular ID to the previous "block"/transaction
        data["prev"] = prev
        # Proof of work parts
        # Is this done in advance or not?
        # data["nonce"] = None
        # data["pow"]   = None

        # what we do ourselves.
        # make the signatures once the inputs/outputs are known
        sigstrings = list()
        for pair in data["input"]:
            content = self.get_sig_content(pair, output)
            signer = Node.nodes[pair[0]]
            signature = signer.sign(content)
            sigstrings.append(signature)

        data["sigs"] = sigstrings

        # hash everything to get the identifier
        identifier = sha256(json.dumps(data))
        data["id"] = identifier
        return data

    def get_output(self, input_pair):
        pkh = input_pair[0]
        offset = input_pair[1]
        return self.chain[pkh][offset]

    def sign(self, m):
        return self.sk.sign(m)

    def get_sig_content(self, input_pair, output):
        out_from_last = self.get_output(input_pair)  # self.chain[pkh][offset]
        return json.dumps(input_pair) + json.dumps(out_from_last) + json.dumps(output)

    @staticmethod
    def proof_of_work(tx):
        serialized = json.dumps(tx)
        # secure randomness is probably unnecessary.
        nonce = random.SystemRandom().randint(1, 100000000000)
        total = serialized + str(nonce)
        hashed = sha256(total)
        while not verify_hash(hashed):
            nonce = random.SystemRandom().randint(1, 100000000000)
            total = serialized + str(nonce)
            hashed = sha256(total)
        return nonce

    def has_double_spend(self, tx):
        curr = self.chain[tx["prev"]]
        while curr is not None:
            # DO THINGS.
            # if something in the output matches, ie double spent...
            for pair in curr["output"]:
                if pair in tx["output"]:
                    return True
            curr = self.chain[tx["prev"]]
        return False

    def io_matches(self, tx):
        amount_in = 0
        for pk, offset in tx["input"]:
            input_tx = self.chain[pk]
            # Transaction
            # -> Outputs [(ID, Amt)s]
            #    -> (ID, Amt)
            #       -> Amt
            amount_in += input_tx["output"][offset][1]

        amount_out = 0
        for pk, amt in tx["output"]:
            amount_out += amt

        return amount_in == amount_out

    def verify(self, tx):
        # need to check:
        # does input match output?
        # is the input verified?
        # did we double spend?
        # is the signature valid?
        pass