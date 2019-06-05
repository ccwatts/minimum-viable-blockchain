import json
import random
import transactions
import thread_util
import threading
import time
from collections import OrderedDict
from ecdsa import SigningKey, VerifyingKey
from Crypto.Hash import SHA256


# from ye olde lab 0
def xor_strings(plaintext, key):
    # key length adjustments
    fit_key = key
    while len(fit_key) < len(plaintext):
        fit_key += key
    fit_key = fit_key[:len(plaintext)]
    # perform xor
    xored = [ord(pc) ^ ord(kc) for pc, kc in zip(plaintext, fit_key)]
    return "".join(chr(xc) for xc in xored)


def sha256(string):
    return SHA256.new(string).hexdigest()


# Extra feature stuff -- an alternative proof of work, using scrypt
def scrypt(string, N=20):
    V = [None for i in range(N)]
    x = sha256(string)
    for i in range(N):
        V[i] = x
        x = sha256(x)
    for i in range(N):
        j = int(x, 16) % N
        x = sha256(xor_strings(x, V[j]))
    return x


def verify_hash(in_hash):
    numerical_value = int(in_hash, 16)
    return numerical_value <= Node.HASH_BOUND


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


class Node(threading.Thread):
    # there is probably a better way to do this.
    # HASH_BOUND = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # HASH_BOUND = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    HASH_BOUND = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    GENESIS_AMOUNT = 25
    all = dict()
    verify_target = None
    verify_queue = list()
    verified = list()
    barrier = thread_util.Barrier(1)
    counter = 1

    # THIS LIKELY HAS TO CHANGE.
    def __init__(self, genesis, utp):
        # placeholders
        threading.Thread.__init__(self)
        self.id = Node.counter
        Node.counter += 1
        self.chain = dict()
        self.tail = list()

        self.accept_genesis(genesis)
        self.utp = utp

        Node.all[self.id] = self

    # take in the start of our chain, assumed valid
    def accept_genesis(self, genesis_tx):
        self.chain = dict()
        self.chain[genesis_tx["NUMBER"]] = genesis_tx
        self.tail = [genesis_tx["NUMBER"]]

    # verify ALL of the signatures of a transaction
    def verify_sigs(self, tx):
        if len(tx["INPUT"]) != len(tx["SIGNATURE"][1]):
            return False
        try:
            assert sha256(tx["TYPE"]) == tx["SIGNATURE"][0]
        except AssertionError:
            return False
        for i in range(len(tx["INPUT"])):
            pair = tx["INPUT"][i]
            content = transactions.TransactionGen.get_sig_content(pair, tx["OUTPUT"])
            output_source = transactions.TransactionGen.get_output(pair)
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

    # do the mining process, attaching relevant fields
    def mine(self, txd):
        tx = OrderedDict(txd)
        tx["PREV"] = self.tail[0]
        nonce, hashed = self.proof_of_work(tx)
        if nonce is None and hashed is None:
            return None
        tx["NONCE"] = nonce
        tx["POW"] = hashed
        if txd in self.utp:
            return tx
        else:
            return None

    # do the proof of work, calling the scrypt function above
    # used to have nonces randomly chosen, now goes from 0 up indefinitely; not sure which is better.
    def proof_of_work(self, tx):
        serialized = json.dumps(tx)
        # secure randomness is probably unnecessary.
        # nonce = random.SystemRandom().randint(1, 100000000000)
        nonce = 0
        total = serialized + str(nonce)
        hashed = scrypt(total)
        while not verify_hash(hashed):
            if self.verify_or_continue():
                if self.is_verified(tx):
                    return None, None
            nonce = nonce + 1  # random.SystemRandom().randint(1, 100000000000)
            total = serialized + str(nonce)
            hashed = scrypt(total)
        return nonce, hashed

    # verify that the work has been done
    @staticmethod
    def verify_pow(tx):
        if tx["POW"] is not None and tx["NONCE"] is not None:
            without_pow = OrderedDict(tx)
            without_pow.pop("POW")
            without_pow.pop("NONCE")
            #without_pow.pop("PREV")
            serialized = json.dumps(without_pow)
            total = serialized + str(tx["NONCE"])
            rehash = scrypt(total)
            return rehash == tx["POW"]
        else:
            return False

    # check if it's in our verified pool
    def is_verified(self, tx):
        for vtx in Node.verified:
            if vtx["NUMBER"] == tx["NUMBER"]:
                return True
        return False

    # does it have a double spend somewhere in the chain?
    # there may be some weirdness with if the tails of forks are "double spends" of each other, but i'm not sure...
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

    # does the input amount match the output amount exactly?
    def io_matches(self, tx):
        amount_in = 0
        for pk, offset in tx["INPUT"]:
            input_tx = transactions.TransactionGen.all[pk]
            # Transaction
            # -> Outputs [(ID, Amt)s]
            #    -> (ID, Amt)
            #       -> Amt
            amount_in += input_tx["OUTPUT"][offset][1]

        amount_out = 0
        for pk, amt in tx["OUTPUT"]:
            amount_out += amt

        return amount_in == amount_out

    # does the input exist purely in the chain we have? this is used to determine whether we should consider a
    # block for mining
    def input_in_chain(self, tx):
        for id, offset in tx["INPUT"]:
            if id not in self.chain.keys():
                return False
        return True

    # does the input for this transaction exist SOMEWHERE? checks our own chain and the utp, which should be
    # exhaustive unless i've missed yet another race condition
    def input_exists(self, tx):
        for id, offset in tx["INPUT"]:
            found = False
            for utx in self.utp:
                if id == utx["NUMBER"]:
                    found = True
                    break
            if not found and id not in self.chain.keys():
                return False
        return True

    # what it says on the tin
    def validate(self, tx):
        # need to check:
        # does input match output?
        # did we double spend?
        # is the signature valid?
        return self.io_matches(tx) and self.verify_sigs(tx) and not self.has_double_spend(tx)

    # what it says on the tin
    def verify(self, tx):
        # is the input verified?
        # assert self.validate(tx)
        # assert self.verify_pow(tx)
        return self.validate(tx) and self.verify_pow(tx)

    # what it says on the tin
    def verify_and_add(self, tx):
        assert self.verify(tx)
        self.add_tx(tx)

    # from below, but just the length
    def chain_length(self, tail):
        return len(self.get_chain_line(tail))

    # get the transactions in a line starting from the end of one fork
    def get_chain_line(self, tail):
        if type(tail) is OrderedDict:
            curr = tail
        else:
            curr = self.chain[tail]
        line = list()
        try:
            while curr is not None:
                # line.append(curr["NUMBER"])
                line.append(curr)
                curr = self.chain[curr["PREV"]]
        except KeyError:
            return line

    def get_line_keys(self, tail):
        return [t["NUMBER"] for t in self.get_chain_line(tail)]

    # adds a transaction itself, which does the fork resolution inside among other things
    # it won't add it if the resulting chain length would be less than the longest current chain length, and similarly
    # prunes any chains that are shorter after the addition of the new transaction
    # at this point, the transaction has already been verified, so additional checks are light
    def add_tx(self, tx):
        tail = None
        # more assumptions, that tail isn't empty + they're all the same
        # if everything functions, that should be true. "SHOULD"
        tail_length = self.chain_length(self.tail[0])
        if tx["PREV"] not in self.chain.keys():
            raise Exception("Tried to add transaction that did not continue a current block of the chain")

        proposed_length = self.chain_length(tx)
        if proposed_length < tail_length:
            tx.pop("POW", None)
            tx.pop("NONCE", None)
            tx.pop("PREV", None)
            if tx not in self.utp:
                self.utp.append(tx)
            return

        for i in range(len(self.tail)):
            if self.tail[i] == tx["PREV"]:
                self.tail[i] = tx["NUMBER"]
                self.chain[tx["NUMBER"]] = tx
                tail = tx
                break

        for number in self.chain.keys():
            if number == tx["PREV"]:
                #self.tail.append(tx["NUMBER"])
                self.chain[tx["NUMBER"]] = tx
                tail = tx
                break

        if tail is None:
            raise Exception("Tried to add transaction that did not continue a current block of the chain")

        # length = self.chain_length(tx)
        new_tail = list()
        new_tail.append(tail["NUMBER"])
        mainline = self.get_chain_line(tail["NUMBER"])
        for old_tail in self.tail:
            # prevent some oddness mid-pruning
            if old_tail in self.chain.keys():
                old_length = self.chain_length(old_tail)
                if old_length >= proposed_length:
                    new_tail.append(old_tail)
                else:
                    print "Pruning tail. (old %d vs %d new)" % (old_length, proposed_length)
                    alt_line = self.get_chain_line(old_tail)
                    outsides = [x for x in alt_line if x not in mainline]
                    for x in outsides:
                        x.pop("NONCE", None)
                        x.pop("POW", None)
                        x.pop("PREV", None)
                        if x not in self.utp:
                            self.utp.append(x)
                        self.chain.pop(x["NUMBER"], None)
        self.tail = new_tail
        return

    # does the synchronization between threads, so everyone's reasonably synced up at each stage when someone mines
    def verify_or_continue(self):
        if len(Node.verify_queue) > 0:
            for tx in Node.verify_queue:
                if tx["NUMBER"] not in self.chain.keys():
                    self.verify_and_add(tx)
            print "%d accepted, chain length %d vs %d in UTP" % (self.id, len(self.chain), len(self.utp))
            Node.barrier.wait()
            return True
        else:
            Node.barrier.wait()
            return False

    def loop(self):
        while len(self.utp) >= 0:
            # exit condition
            if len(self.utp) == 0:
                # if it's empty, wait and see if we have something in 5 seconds
                time.sleep(5)
                if len(self.utp) == 0:
                    # if not, exit.
                    break
            # pick something at random from the pool
            pick = random.choice(self.utp)
            if self.validate(pick):
                # if it's a valid transaction...
                if self.input_in_chain(pick):
                    # if its input is currently inside our chain...
                    if self.verify_or_continue():
                        # do a check inside, if we've already been notified of a new verified tx before we mine,
                        # drop what we're doing any just add that
                        continue
                    # otherwise, go ahead and mine
                    print "%d mining" % self.id
                    mined = self.mine(pick)
                    # if we got word during the proof of work process that the block we were mining was already mined
                    if mined is None:
                        # then just exit
                        continue

                    # more checks.
                    # the structure is a little different, since for this we want to not only check whether we've had
                    # there's a race condition here that this is trying to prevent where two blocks simultaneously
                    # mine the same block, and double-send the heads-up to add new verified messages, but only single
                    # adds the actual message, so they don't properly unblock b/c they don't see anything new
                    self.verify_or_continue()
                    already_adding = False
                    for tx in Node.verify_queue:
                        if tx["NUMBER"] == mined["NUMBER"]:
                            already_adding = True
                    if already_adding:
                        continue
                    # if we get past all that mess, we're done with the mining process, so alert everyone to add it
                    # when they can
                    print "%d done mining, alerting rest (%d left in UTP)" % (self.id, len(self.utp))
                    # barrier to have everyone stop what they're doing whenever they check until everyone's done
                    Node.barrier = thread_util.Barrier(len(Node.all))
                    Node.verify_queue.append(mined)
                    # done, do the check and add ourselves
                    self.verify_or_continue()
                    # reset target, remove from pool
                    Node.verify_queue.remove(mined)
                    Node.verified.append(mined)
                    try:
                        self.utp.remove(pick)
                    except ValueError:
                        # more race condition stuff, yay.
                        print "(already discarded)"
                    # wait another 0-2 seconds
                    #time.sleep(random.randint(0, 2))
                elif not self.input_exists(pick):
                    # if the input doesn't exist in any pool, then we bail (after a check)
                    self.verify_or_continue()
                    try:
                        self.utp.remove(pick)
                    except ValueError:
                        print "(already discarded)"
            else:
                # it's invalid for other reasons, so dump it
                print "%d discarding invalid tx" % self.id
                self.verify_or_continue()
                try:
                    self.utp.remove(pick)
                except ValueError:
                    print "(already discarded)"

        # wait to sync up the printing
        time.sleep(self.id)
        self.print_chain()

    def print_chain(self):
        print "=== %d's chain ===" % self.id
        keys = self.get_line_keys(self.tail[0])
        for k in keys:
            print k
        print "Length: %d\n" % self.chain_length(self.tail[0])

    def run(self):
        print "Starting loop for %d" % self.id
        self.loop()
