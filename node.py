import json
import random
import transactions
from collections import OrderedDict
from ecdsa import SigningKey, VerifyingKey
from Crypto.Hash import SHA256


def sha256(string):
    return SHA256.new(string).hexdigest()


def verify_hash(in_hash):
    numerical_value = int(in_hash, 16)
    return numerical_value < Node.HASH_BOUND


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




class Node:
    # there is probably a better way to do this.
    #HASH_BOUND = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    HASH_BOUND = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    GENESIS_AMOUNT = 25
    all = dict()

    # THIS LIKELY HAS TO CHANGE.
    def __init__(self):
        # placeholders
        self.sk = SigningKey.generate()
        self.pk = self.sk.get_verifying_key()
        self.pkh = self.pk.to_string().encode("hex") #sha256(self.pk.to_string())
        self.chain = dict()
        self.tail = list()
        Node.all[self.pkh] = self

    def accept_genesis(self, genesis_tx):
        self.chain = dict()
        self.chain[genesis_tx["NUMBER"]] = genesis_tx
        self.tail = [genesis_tx["NUMBER"]]

    def verify_sigs(self, tx):
        if len(tx["INPUT"]) != len(tx["SIGNATURE"][1]):
            return False

        try:
            assert sha256(tx["TYPE"]) == tx["SIGNATURE"][0]
        except AssertionError:
            return False

        for i in range(len(tx["INPUT"])):
            pair = tx["INPUT"][i]
            content = transactions.TransactionPool.get_sig_content(pair, tx["OUTPUT"])
            output_source = transactions.TransactionPool.get_output(pair)
            pk = VerifyingKey.from_string(output_source[0].decode("hex"))
            # signer = Identity.all[output_source[0]]
            decoded_sig = tx["SIGNATURE"][1][i].decode("hex")
            try:
                pk.verify(decoded_sig, content)
                # signer.pk.verify(decoded_sig, content)
            except Exception as e:
                print(e)
                return False
        return True

    def mine(self, tx):
        nonce, hashed = Node.proof_of_work(tx)
        tx["nonce"] = nonce
        tx["pow"] = hashed
        # TODO TEMP.
        tx["PREV"] = self.tail[0]
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
            without_pow.pop("PREV")
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
            input_tx = transactions.TransactionPool.all[pk]
            # Transaction
            # -> Outputs [(ID, Amt)s]
            #    -> (ID, Amt)
            #       -> Amt
            amount_in += input_tx["OUTPUT"][offset][1]

        amount_out = 0
        for pk, amt in tx["OUTPUT"]:
            amount_out += amt

        return amount_in == amount_out

    def input_in_chain(self, tx):
        for id, offset in tx["INPUT"]:
            if id not in self.chain.keys():
                return False
        return True

    def input_exists(self, tx, utp):
        for id, offset in tx["INPUT"]:
            found = False
            for utx in utp:
                if id == utx["NUMBER"]:
                    found = True
                    break
            if not found and id not in self.chain.keys():
                return False
        return True

    def validate(self, tx):
        # need to check:
        # does input match output?
        # did we double spend?
        # is the signature valid?
        return self.io_matches(tx) and self.verify_sigs(tx) and not self.has_double_spend(tx)

    def verify(self, tx):
        # is the input verified?
        assert self.validate(tx)
        assert self.verify_pow(tx)
        return True

    def verify_and_add(self, tx):
        assert self.verify(tx)
        self.add_tx(tx)

    def chain_length(self, tail):
        return len(self.get_chain_line(tail))
        #if type(tail) is OrderedDict:
        #    curr = tail
        #else:
        #    curr = self.chain[tail]
        #length = 1
        #try:
        #    while curr is not None:
        #        length += 1
        #        curr = self.chain[curr["PREV"]]
        #except KeyError:
        #    return length

    def get_chain_line(self, tail):
        if type(tail) is OrderedDict:
            curr = tail
        else:
            curr = self.chain[tail]
        line = list()
        #line.append(curr["NUMBER"])
        try:
            while curr is not None:
                line.append(curr["NUMBER"])
                curr = self.chain[curr["PREV"]]
        except KeyError:
            return line

    def add_tx(self, tx):
        tail = None
        for i in range(len(self.tail)):
            if self.tail[i] == tx["PREV"]:
                self.tail[i] = tx["NUMBER"]
                self.chain[tx["NUMBER"]] = tx
                tail = tx
                break
        if tail is None:
            raise Exception("Tried to add transaction that did not continue a current tail of the chain")

        length = self.chain_length(tx)
        new_tail = list()
        new_tail.append(tail["NUMBER"])
        mainline = self.get_chain_line(tail["NUMBER"])
        for old_tail in self.tail:
            if self.chain_length(old_tail) >= length:
                new_tail.append(old_tail)
            else:
                altline = self.get_chain_line(old_tail)
                outsides = [x for x in altline if x not in mainline]
                for x in outsides:
                    self.chain.pop(x, None)
        self.tail = new_tail
        return

    def loop(self, utp):
        while len(utp) > 0:
            pick = random.choice(utp)

            if self.validate(pick):
                if self.input_in_chain(pick):
                    print "mining"
                    self.mine(pick)
                    self.add_tx(pick)
                    #temp...
                    for n in Node.all.values():
                        if n != self:
                            n.verify_and_add(pick)
                    utp.remove(pick)
                elif not self.input_exists(pick, utp):
                    utp.remove(pick)
            else:
                print "Discarding invalid tx"
                utp.remove(pick)
                # allDone = True
                # for tx in utp:
                #     if self.validate(tx):
                #         allDone = False
                #         break
                # if allDone:
                #     print "All remaining transactions are invalid. Aborting."
                #     break

        self.print_chain()

    def print_chain(self):
        print "=== CHAIN ==="
        for k, v in self.chain.items():
            print k
        # kinda assuming there's only one tail here...
        print self.chain_length(self.tail[0])

    def single_tx(self, utp):
        try:
            pick = random.choice(utp)

            if self.validate(pick):
                if self.input_in_chain(pick):
                    print "mining"
                    self.mine(pick)
                    self.add_tx(pick)
                    #temp...
                    return pick
                elif not self.input_exists(pick, utp):
                    utp.remove(pick)
            else:
                print "Discarding invalid tx"
                utp.remove(pick)
                # allDone = True
                # for tx in utp:
                #     if self.validate(tx):
                #         allDone = False
                #         break
                # if allDone:
                #     print "All remaining transactions are invalid. Aborting."
                #     break
            self.print_chain()
            return None
        except:
            print "failed to process transaction"

    def verify_single(self, utp, pick):
        for n in Node.all.values():
            if n != self:
                n.verify_and_add(pick)
        utp.remove(pick)
