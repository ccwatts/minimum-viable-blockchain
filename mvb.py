import node
import transactions


if __name__ == "__main__":
    nodes = list()
    try:
        genesis, pool = transactions.TransactionGen.load_transactions()
        print "Loaded from transactions.json"
    except IOError:
        genesis, pool = transactions.TransactionGen.generate_io_chain()
        print "Generated new chain"
    for i in range(10):
        n = node.Node(genesis, pool)
        nodes.append(n)

    for n in nodes:
        n.start()
