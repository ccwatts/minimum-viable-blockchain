from transactions import *
import json
import random
from collections import OrderedDict
from ecdsa import SigningKey, VerifyingKey
from Crypto.Hash import SHA256


def sha256(string):
    return SHA256.new(string).hexdigest()


def verify_hash(in_hash):
    numerical_value = int(in_hash, 16)
    return numerical_value < Node.HASH_BOUND


def get_output(input_pair):
    tx_id = input_pair[0]
    offset = input_pair[1]
    return Transactions.all[tx_id]["OUTPUT"][offset]


def get_sig_content(input_pair, output):
#    out_from_last = get_output(input_pair)  # self.chain[pkh][offset]
#    return str(json.dumps(input_pair) + json.dumps(out_from_last) + json.dumps(output))
    return str(json.dumps(input_pair) + json.dumps(output))


def get_id_content(inputs, outputs, sigs):
    return str(json.dumps(inputs) + json.dumps(outputs) + json.dumps(sigs))


def sign(sk, m):
    return sk.sign(m).encode("hex")


def verify(pk_hex, m, sig):
    decoded = sig.decode("hex")
    try:
        pk = VerifyingKey.from_string(pk_hex.decode("hex"))
        pk.verify(m, decoded)
        return True
    except AssertionError:
        return False

class Identity:
    all = dict()
    def __init__(self):
        # placeholders
        self.sk = SigningKey.generate()
        self.pk = self.sk.get_verifying_key()
        self.pkh = self.pk.to_string().encode("hex")
        Identity.all[self.pkh] = self

    def sign(self, m):
        return sign(self.sk, m)

    def verify(self, m, sig):
        return verify(self.pkh, m, sig)

    def make_transaction(self, inputs, outputs, prev):
        data = OrderedDict()
        # List of (ID hash, Offset) pairs
        data["INPUT"] = inputs
        # List of (ID hash, Amount) pairs
        data["OUTPUT"] = outputs
        # A singular ID to the previous "block"/transaction
        # Wrap in an if statement so we can feed either the tx itself or its id
        if type(prev) is dict:
            data["PREV"] = prev["NUMBER"]
        else:
            data["PREV"] = prev
        # what we do ourselves.
        # make the signatures once the inputs/outputs are known
        sigstrings = list()
        for pair in data["INPUT"]:
            content = get_sig_content(pair, outputs)
            output_source = get_output(pair)
            signer = Identity.all[output_source[0]]
            signature = signer.sign(content)
            sigstrings.append(signature)

        data["SIGNATURE"] = sigstrings

        # hash everything to get the identifier
        id_target = get_id_content(inputs, outputs, sigstrings)
        identifier = sha256(json.dumps(id_target))
        data["NUMBER"] = identifier
        Transactions.all[identifier] = data
        return data


class Node:
    # there is probably a better way to do this.
    HASH_BOUND = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    GENESIS_AMOUNT = 25
    all = dict()

    # THIS LIKELY HAS TO CHANGE.
    def __init__(self):
        # placeholders
        self.sk = SigningKey.generate()
        self.pk = self.sk.get_verifying_key()
        self.pkh = self.pk.to_string().encode("hex") #sha256(self.pk.to_string())
        self.chain = None
        self.tail = None
        Node.all[self.pkh] = self

    def accept_genesis(self, genesis_tx):
        self.chain = dict()
        self.chain[genesis_tx["NUMBER"]] = genesis_tx
        self.tail = [genesis_tx["NUMBER"]]

    def verify_sigs(self, tx):
        if len(tx["INPUT"]) != len(tx["SIGNATURE"]):
            return False
        for i in range(len(tx["INPUT"])):
            pair = tx["INPUT"][i]
            content = get_sig_content(pair, tx["OUTPUT"])
            output_source = get_output(pair)
            pk = VerifyingKey.from_string(output_source[0].decode("hex"))
            # signer = Identity.all[output_source[0]]
            decoded_sig = tx["SIGNATURE"][i].decode("hex")
            try:
                pk.verify(decoded_sig, content)
                # signer.pk.verify(decoded_sig, content)
            except AssertionError:
                return False
        return True

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
                    for pair in curr["INPUT"]:
                        if pair in tx["INPUT"]:
                            return True
                    curr = self.chain[curr["PREV"]]
            except KeyError:
                continue
        return False

    def io_matches(self, tx):
        amount_in = 0
        for pk, offset in tx["INPUT"]:
            input_tx = self.chain[pk]
            # Transaction
            # -> Outputs [(ID, Amt)s]
            #    -> (ID, Amt)
            #       -> Amt
            amount_in += input_tx["OUTPUT"][offset][1]

        amount_out = 0
        for amt, pk in tx["OUTPUT"]:
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
            if self.tail[i] == tx["PREV"]:
                self.tail[i] = tx["NUMBER"]
                self.chain[tx["NUMBER"]] = tx
                continues = True
                break
        if not continues:
            raise Exception("Tried to add transaction that did not continue a current tail of the chain")