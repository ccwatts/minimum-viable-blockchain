from node import *
import json
import random
from collections import OrderedDict


class Transactions:
    def __init__(self):
        # get all the identities we need
        while len(Identity.all) < 5:
            Identity()

    def make_genesis(self):
        gen = dict()
        recipient = random.choice(Identity.all.items())
        output = (Node.GENESIS_AMOUNT, recipient.pkh)
        gen["TYPE"] = "TRANS"
        gen["INPUT"] = list()
        gen["OUTPUT"] = [output]
        sigs = list()


        pass

