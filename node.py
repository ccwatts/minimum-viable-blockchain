import json
import random
from collections import OrderedDict
from ecdsa import SigningKey
from Crypto.Hash import SHA256



def sha256(string):
    return SHA256.new(string).hexdigest()

def verify_hash(in_hash):
    numerical_value = int(in_hash, 16)
    return numerical_value < Node.HASH_BOUND

class Node:
    # there is probably a better way to do this.
    HASH_BOUND = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    COINBASE_AMOUNT = 25
    nodes = dict()
    def __init__(self):
        # placeholders
        self.sk = SigningKey.generate()
        self.pk = self.sk.get_verifying_key()
        self.pkh = sha256(self.pk.to_string())
        self.chain = None
        self.tail = None
        Node.nodes[self.pkh] = self

    def accept_coinbase(self, coinbase_tx):
        self.chain = dict()
        self.chain[coinbase_tx["id"]] = coinbase_tx
        self.tail = [coinbase_tx["id"]]

    def make_transaction(self, inputs, output, prev):  # , nonce, powork):
        data = OrderedDict()
        # List of (ID hash, Offset) pairs
        data["inputs"] = inputs
        # List of (ID hash, Amount) pairs
        data["outputs"] = output
        # A singular ID to the previous "block"/transaction
        # Wrap in an if statement so we can feed either the tx itself or its id
        if type(prev) is dict:
            data["prev"] = prev["id"]
        else:
            data["prev"] = prev
        # Proof of work parts
        # Is this done in advance or not?
        # data["nonce"] = None
        # data["pow"]   = None

        # what we do ourselves.
        # make the signatures once the inputs/outputs are known
        sigstrings = list()
        for pair in data["inputs"]:
            content = self.get_sig_content(pair, output)
            output_source = self.get_output(pair)
            signer = Node.nodes[output_source[0]]
            signature = signer.sign(content)
            sigstrings.append(signature)

        data["sigs"] = sigstrings

        # hash everything to get the identifier
        identifier = sha256(json.dumps(data))
        data["id"] = identifier
        return data

    def get_output(self, input_pair):
        tx_id = input_pair[0]
        offset = input_pair[1]
        return self.chain[tx_id]["outputs"][offset]

    def sign(self, m):
        return self.sk.sign(m).encode("hex")

    def verify_sigs(self, tx):
        if len(tx["inputs"]) != len(tx["sigs"]):
            return False
        for i in range(len(tx["inputs"])):
            pair = tx["inputs"][i]
            content = self.get_sig_content(pair, tx["outputs"])
            output_source = self.get_output(pair)
            signer = Node.nodes[output_source[0]]
            decoded_sig = tx["sigs"][i].decode("hex")
            try:
                signer.pk.verify(decoded_sig, content)
            except AssertionError:
                return False
        return True

    def get_sig_content(self, input_pair, output):
        out_from_last = self.get_output(input_pair)  # self.chain[pkh][offset]
        return str(json.dumps(input_pair) + json.dumps(out_from_last) + json.dumps(output))

    @staticmethod
    def mine(tx):
        nonce, hashed = Node.proof_of_work(tx)
        tx["nonce"] = nonce
        tx["pow"] = hashed
        # need to do announcement stuff here
        return tx

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
        return nonce, hashed

    @staticmethod
    def verify_pow(tx):
        if tx["pow"] is not None and tx["nonce"] is not None:
            without_pow = OrderedDict(tx)
            without_pow.pop("pow")
            without_pow.pop("nonce")
            serialized = json.dumps(without_pow)
            total = serialized + str(tx["nonce"])
            rehash = sha256(total)
            return rehash == tx["pow"]
        else:
            return False

    def has_double_spend(self, tx):
        for tail in self.tail:
            try:
                curr = self.chain[tail]
                while curr is not None:
                    # DO THINGS.
                    # if something in the output matches, ie double spent...
                    for pair in curr["inputs"]:
                        if pair in tx["inputs"]:
                            return True
                    curr = self.chain[curr["prev"]]
            except KeyError:
                continue
        return False

    def io_matches(self, tx):
        amount_in = 0
        for pk, offset in tx["inputs"]:
            input_tx = self.chain[pk]
            # Transaction
            # -> Outputs [(ID, Amt)s]
            #    -> (ID, Amt)
            #       -> Amt
            amount_in += input_tx["outputs"][offset][1]

        amount_out = 0
        for pk, amt in tx["outputs"]:
            amount_out += amt

        return amount_in == amount_out

    def validate(self, tx):
        # need to check:
        # does input match output?
        # did we double spend?
        # is the signature valid?
        return self.io_matches(tx) and self.verify_sigs(tx) and not self.has_double_spend(tx)

    def verify(self, tx):
        # is the input verified?
        return self.validate(tx) and self.verify_pow(tx)

    def add_tx(self, tx):
        continues = False
        for i in range(len(self.tail)):
            if self.tail[i] == tx["prev"]:
                self.tail[i] = tx["id"]
                self.chain[tx["id"]] = tx
                continues = True
                break
        if not continues:
            raise Exception("Tried to add transaction that did not continue a current tail of the chain")