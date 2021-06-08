from hashlib import sha256


class MerkleTree:

    def __init__(self):
        """
        size - the numbers of leaf in the tree
        also it initiate the tree as empty in the begin
        """
        self.size = 0  # number of leaf nodes in tree
        self.initiate_tree()  # create empty mht

    def add_leaf(self, string):
        hash_leaf = self.hash(string)
        self.size += 1
        self._storeNode(self.size - 1, self.size, hash_leaf)
        print(string + " is hashed to the value :" + hash_leaf)

    def mth(self, k1, k2):
        """ Merkle Tree Hash funcion recursively creates required nodes"""
        try:
            mNode = self._retrieveNode(k1, k2)
        except KeyError as v:  # no stored node, so make one
            k = k1 + largestPower2(k2 - k1)
            mNode = self.hash(self.mth(k1, k) + self.mth(k, k2))
            self._storeNode(k1, k2, mNode)
        return mNode

    def auditPath(self, m, n=None):
        """ return a list of hash values for entry d(m) that proves
            that d(m) is contained in the nth root hash with 0 <= m < n
        """
        if not n:
            n = self.size

        def _auditPath(m, k1, k2):
            """ Recursively collect audit path """
            if (k2 - k1) == 1:
                return []  # terminate with null list when range is a single node
            k = k1 + largestPower2(k2 - k1)
            if m < k:
                path = _auditPath(m, k1, k) + [("1" + self.mth(k, k2)), ]
            else:
                path = _auditPath(m, k, k2) + [("0" + self.mth(k1, k)), ]
            return path

        return _auditPath(m, 0, n)

    def validPath(self, m, leaf_hash, root_hash, audit_path, n=None):
        """ Test if leaf_hash is contained under a root_hash
            as demonstrated by the audit_path """
        edge_list = list(audit_path.split(" "))
        for edge in edge_list:
            side = edge[0:1]
            leaf = edge[1:len(edge)]
            if side == "0":
                leaf_hash = self.hash(leaf + leaf_hash)
            else:
                leaf_hash = self.hash(leaf_hash + leaf)

        if leaf_hash == root_hash:
            return True
        else:
            return False

    def rootHash(self, n=None):
        """ Root hash of tree for nth root """
        if not n:
            n = self.size
        if n > 0:
            return self.mth(0, n)
        else:
            return self.hash('')  # empty tree is hash of null string

    def leafHash(self, m):
        """ Leaf hash value for mth entry """
        return self.mth(m, m + 1)

    def hash(self, input):
        """ Wrapper for hash functions """
        return sha256(input.encode('utf-8')).hexdigest()

    # Overload the following for persistant trees
    def initiate_tree(self):
        self.hash_tree = {}

    def _retrieveNode(self, k1, k2):
        return self.hash_tree[(k1, k2)]

    def _storeNode(self, k1, k2, mNode):
        # leaf and non-leaf nodes in the same dictionary indexed by range tuple
        assert k1 < k2 <= self.size
        self.hash_tree[(k1, k2)] = mNode


def largestPower2(n):
    """ Return the largest power of 2 less than n """
    lp2 = 1
    while lp2 < n:
        lp2 = lp2 << 1
    return lp2 >> 1


def parse_user_input(user_in, secondary_input=False):
    if not secondary_input:
        if user_in.__contains__(" "):
            number, string = user_in.split(sep=" ", maxsplit=1)
        else:
            return user_in, None
    else:
        number, string = user_in.split(sep=" ", maxsplit=1)
        if string is not None:
            string = string.split(" ")
    return number, string


def prepare_result_to_print(root, path):
    single_list = root
    if not path:
        return single_list
    for node in range(len(path)):
        single_list += " "
        single_list += path[node]
    return single_list


def parse_user_path_input(user_in):
    root, path = user_in.split(sep=" ", maxsplit=1)
    return root, path


if __name__ == '__main__':

    merkle_tree = MerkleTree()

    while True:
        user_input = input()
        user_number_choice, user_string = parse_user_input(user_input)  # TODO: is it possiable to get space in the data
        if user_number_choice.__eq__('0'):
            print("the number is " + user_input)
        elif user_number_choice.__eq__('1'):
            test = sha256(user_string.encode('utf-8')).hexdigest()
            merkle_tree.add_leaf(string=user_string)
        elif user_number_choice.__eq__('2'):
            print(merkle_tree.rootHash())
        elif user_number_choice.__eq__('3'):
            path_list = merkle_tree.auditPath(int(user_string))
            list_to_print = prepare_result_to_print(root=merkle_tree.rootHash(), path=path_list)
            print(list_to_print)
        elif user_number_choice.__eq__('4'):
            user_input = input()
            tree_root, leaf_path = parse_user_path_input(user_input)
            print(merkle_tree.validPath(2, merkle_tree.hash(user_string), tree_root, leaf_path))
        elif user_number_choice.__eq__('exit'):
            print("bye bye! ")
            break
