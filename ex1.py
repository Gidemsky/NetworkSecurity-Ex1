import base64
import math
from hashlib import sha256
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode


class NodeLeaf:
    """
    the basic leaf class
    """
    def __init__(self, leaf_number, val):
        self.leaf_index = leaf_number
        self.hash = val


class MerkleTree:

    def __init__(self, is_sparse=False, default="0"):
        """
        size - the numbers of leaf in the tree
        also it initiate the tree as empty in the begin
        """
        self.is_sparse = is_sparse

        self.hash_tree = {}
        self.size = 0

        self.default_hash_level = {}

        self.leaf_to_change_digested_root = None
        self.signed_leaf_numbers = []

        self.node_to_be_calc = []
        self.default_leaf_Value = default

    def add_leaf(self, leaf_data):
        """
        add lead to the tree and hash the data
        :param leaf_data: the data to add and to hash
        :return:
        """
        if self.is_sparse:
            # in case i need it
            is_leaf_added = False
            self.leaf_to_change_digested_root = "{0:08b}".format(int(leaf_data, 16))

            user_leaf_number = int(leaf_data, 16)
            for leaf_number in self.signed_leaf_numbers:
                if leaf_number.leaf_index == user_leaf_number:
                    is_leaf_added = True
                    break

            if not is_leaf_added:
                self.hash_tree[user_leaf_number] = "1"
                # add the leaf to the list of leaf that has been signed
                self.signed_leaf_numbers.append(NodeLeaf(user_leaf_number, "1"))

        else:
            hash_leaf = hash256(leaf_data)
            self.size += 1
            # store the hashed lead as tree node in the following format:
            # (i , i+1)
            self.save_node(self.size - 1, self.size, hash_leaf)

    def init_defaults(self):
        i = 255
        leaf_value = "0"
        while i >= 0:
            e = hash256(leaf_value + leaf_value)
            leaf_value = e
            self.default_hash_level[i] = e
            i -= 1

    def merkle_tree_calculation(self, l_index=None, r_index=None):
        """
        calculate recursively the nodes and create new one in case it doesn't exist
        :param l_index:
        :param r_index:
        :return: the node number (l_index , r_index)
        """
        if self.is_sparse:
            # in the sparse case it calculates the next level
            temp = []
            tempHash = ""
            for x in self.node_to_be_calc:
                flag = False
                # even leaf case - checking if the brother is marked and calculating the hash accordingly
                # otherwise - calculate the hash with the default value
                if x.leaf_index % 2 == 0:
                    for y in self.node_to_be_calc:
                        if y.leaf_index == x.leaf_index + 1:
                            tempHash = hash256(x.hash + y.hash)
                            self.node_to_be_calc.remove(y)
                            flag = True
                    if not flag:
                        tempHash = hash256(x.hash + self.default_leaf_Value)
                # odd leaf case - checking if the brother is marked and calculating the hash accordingly
                # otherwise - calculate the hash with the default value
                elif x.leaf_index % 2 == 1:
                    for y in self.node_to_be_calc:
                        if y.leaf_index == x.leaf_index - 1:
                            tempHash = hash256(y.hash + x.hash)
                            self.node_to_be_calc.remove(y)
                            flag = True
                    if not flag:
                        tempHash = hash256(self.default_leaf_Value + x.hash)
                leafIndex = math.floor(x.leaf_index / 2)
                temp.append(NodeLeaf(leafIndex, tempHash))
            self.node_to_be_calc = temp.copy()
            self.default_leaf_Value = hash256(self.default_leaf_Value + self.default_leaf_Value)
        else:
            try:
                merkle_node = self.get_node(l_index, r_index)
            except KeyError:
                shared_index = l_index + closest_power(r_index - l_index)
                merkle_node = hash256(self.merkle_tree_calculation(l_index, shared_index)
                                      + self.merkle_tree_calculation(shared_index, r_index))
                self.save_node(l_index, r_index, merkle_node)
            return merkle_node

    def rec_find_proof_of_inclusion(self, node_to_proof, left, right):
        """
        collects recursively the proof path to node_to_proof
        :param node_to_proof:
        :param left: node left index
        :param right: node right index
        :return:
        """
        # checks if the range is of one node. in such case return empty list
        if (right - left) == 1:
            return []
        k = left + closest_power(right - left)
        if node_to_proof < k:
            proof_path = self.rec_find_proof_of_inclusion(node_to_proof, left, k) + [
                ("1" + self.merkle_tree_calculation(k, right)), ]
        else:
            proof_path = self.rec_find_proof_of_inclusion(node_to_proof, k, right) + [
                ("0" + self.merkle_tree_calculation(left, k)), ]
        return proof_path

    def find_proof_of_inclusion(self, node_to_proof):
        """
        returns a list of hashed value
        :param node_to_proof: the node we look for to prove it contains to the tree
        :return: the path proof
        """

        if self.is_sparse:
            '''creating proof for given digest. checking if the brother leaf or itself are marked and adding the hash
            to the proof. If they are not existed - skip until they are existed'''
            self.node_to_be_calc = self.signed_leaf_numbers.copy()
            self.default_leaf_Value = "0"
            proof = ""
            # special case - check if sparse tree is empty
            if len(self.signed_leaf_numbers) == 0:
                proof = self.tree_root_calculate() + " " + self.tree_root_calculate()
                return proof
            tempIndex = int(node_to_proof, 16)
            # create proof 255 times without the root
            for i in range(256):
                broExist = False
                iExist = False
                if tempIndex % 2 == 0:
                    for y in self.node_to_be_calc:
                        if y.leaf_index == tempIndex + 1:
                            proof = proof + " " + y.hash
                            broExist = True
                        elif y.leaf_index == tempIndex:
                            iExist = True
                    if (not broExist) and iExist:
                        proof = proof + " " + self.default_leaf_Value
                elif tempIndex % 2 == 1:
                    for y in self.node_to_be_calc:
                        if y.leaf_index == tempIndex - 1:
                            proof = proof + " " + y.hash
                            broExist = True
                        elif y.leaf_index == tempIndex:
                            iExist = True
                    if (not broExist) and iExist:
                        proof = proof + " " + self.default_leaf_Value
                # in case of last iteration - do not create the next level
                if i != 255:
                    self.merkle_tree_calculation()
                    tempIndex = math.floor(tempIndex / 2)
            # special case - if we found that half of the tree is empty - create the proof accordingly
            if proof == "":
                if tempIndex % 2 == 0:
                    proof = self.default_leaf_Value + " " + self.node_to_be_calc[0].hash
                else:
                    proof = self.node_to_be_calc[0].hash + " " + self.default_leaf_Value
            proof = self.tree_root_calculate() + " " + proof
            return proof
        else:
            return self.rec_find_proof_of_inclusion(node_to_proof, 0, self.size)

    def validate_proof_of_inclusion(self, leaf_hash, root_hash, proof_of_inclusion):
        """
        checks if the proof of inclusion to leaf is true or not
        :param leaf_hash: the leaf to check if the path is true
        :param root_hash: the tree root
        :param proof_of_inclusion: the path
        :return: true or false
        """
        if self.is_sparse:
            """create proof by given digest and check if we need to mark the leaf. Then we check if the proof
            is match to the given proof"""
            # spliting input to array, poping the empty last element, and creating a tree for the proof validation
            parseInput = proof_of_inclusion.split(" ")
            # parseInput.pop()
            proofLength = len(parseInput)
            tmp = MerkleTree(True)

            # in case sign is 1 mark the give leaf
            if root_hash == "1":
                tmp.add_leaf(leaf_hash)
            tmp.node_to_be_calc = tmp.signed_leaf_numbers.copy()

            # if sign was 0, then creating hash value of zeroes, in case was 1, creating hashes of the given digest
            zero = "0"
            for i in range(256 - (proofLength - 2)):
                if root_hash == "1":
                    tmp.merkle_tree_calculation()
                elif root_hash == "0":
                    zero = hash256(zero + zero)

            # in case sign is zero, check if given first node in proof is equal to the calculated zeroes hash
            # in case sign is one check if given second node in proof is equal to the calculated digest hash
            if root_hash == "0":
                if (zero != parseInput[1]):
                    return False
            if root_hash == "1":
                if tmp.node_to_be_calc[0].hash != parseInput[2]:
                    return False

            # Poping out the root, the given first node which is the zeroes hash and calculating the index of
            # the digest after the hashes
            root = parseInput.pop(0)
            tmpHash = parseInput.pop(0)
            tempIndex = int(leaf_hash, 16)
            for p in range(257 - (proofLength - 2)):
                tempIndex = math.floor(tempIndex / 2)

            # according to given diget hash index concating the hashes and compute them
            for x in parseInput:
                if tempIndex % 2 == 1:
                    tmpHash = hash256(x + tmpHash)
                else:
                    tmpHash = hash256(tmpHash + x)

            # after hashing all of the proof, check if we got the root
            if tmpHash != root:
                return False
            return True

        edge_list = list(proof_of_inclusion.split(" "))
        for edge in edge_list:
            side = edge[0:1]
            leaf = edge[1:len(edge)]
            if side == "0":
                leaf_hash = hash256(leaf + leaf_hash)
            else:
                leaf_hash = hash256(leaf_hash + leaf)

        if leaf_hash == root_hash:
            return True
        else:
            return False

    def tree_root_calculate(self):
        """
        calculates the root of the tree.
        if it empty so return empty string
        :return: the tree root. thus means node number (0, tree size)
        """
        if self.is_sparse:
            if len(self.signed_leaf_numbers) == 0:
                return self.default_hash_level[0]
            else:
                self.node_to_be_calc = self.signed_leaf_numbers.copy()
                self.default_leaf_Value = "0"
                for i in range(256):
                    self.merkle_tree_calculation()
                return self.node_to_be_calc[0].hash

        if self.size > 0:
            return self.merkle_tree_calculation(0, self.size)
        else:
            return ""

    def get_node(self, k1, k2):
        return self.hash_tree[(k1, k2)]

    def save_node(self, l_index, r_index, hashed_node):
        """
        Saves all the nodes into the dictionary in the following format:
        [i , i+1] = hashed data
        :param l_index: left index
        :param r_index: right index
        :param hashed_node: the hashed data
        :return:
        """
        assert l_index < r_index <= self.size  # TODO: check if it needed
        self.hash_tree[(l_index, r_index)] = hashed_node


def closest_power(number):
    """
    a util function that helps to find the closest biggest power 2 to n
    :param number:
    :return:
    """
    """ Return the largest power of 2 less than n """
    biggest_power = 1
    while biggest_power < number:
        biggest_power = biggest_power << 1
    return biggest_power >> 1


def parse_user_input(user_in):
    """
    parse first user input into number and some string
    :param user_in: all the user input to parse
    :return: parse data. the number and the string
    """
    if user_in.__contains__(" "):
        number, string = user_in.split(sep=" ", maxsplit=1)
    else:
        return user_in, None
    return number, string


def prepare_result_to_print(root, path):
    """
    responsible to print the result as following: root + path
    :param root:
    :param path:
    :return:
    """
    single_list = root
    if not path:
        return single_list
    for node in range(len(path)):
        single_list += " "
        single_list += path[node]
    return single_list


def parse_user_path_input(user_in):
    """
    in case of input 4, this function returns the root from the input and the path to validate
    :param user_in: user input to validate
    :return: separate root and path
    """
    user_data_input, root, path = user_in.split(sep=" ", maxsplit=2)
    return user_data_input, root, path


def generatePem(passphrase=None):
    if passphrase:
        algorithm = serialization.BestAvailableEncryption(password=passphrase.encode('utf-8'))
    else:
        algorithm = serialization.NoEncryption()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=algorithm)

    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"{private_pem.decode()}\n{public_pem.decode()}")


def signRoot(pr_key,root):
    pr_key = serialization.load_pem_private_key(pr_key.encode(), password=None)
    if root is not None:
        signature = pr_key.sign(
            root.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    return b64encode(signature).decode()


def verify(pub_key, signature, msg):
    
    pub_key = serialization.load_pem_public_key(pub_key.encode())
    try:
        pub_key.verify(
            base64.decodebytes(signature.encode()),
            msg.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except InvalidSignature:
        return False


def hash256(node_data):
    """
    takes the data and make hash using sha 256 to this data
    :param node_data: the data to do the hash to
    :return: hashed data
    """
    return sha256(node_data.encode('utf-8')).hexdigest()


if __name__ == '__main__':

    merkle_tree = MerkleTree()
    sparse_merkle_tree = MerkleTree(True)
    sparse_merkle_tree.init_defaults()

    while True:
        user_input = input()
        user_number_choice, user_string = parse_user_input(user_input)

        if user_number_choice.__eq__('1'):
            merkle_tree.add_leaf(leaf_data=user_string)
        elif user_number_choice.__eq__('2'):
            print(merkle_tree.tree_root_calculate())
        elif user_number_choice.__eq__('3'):
            path_list = merkle_tree.find_proof_of_inclusion(int(user_string))
            list_to_print = prepare_result_to_print(root=merkle_tree.tree_root_calculate(), path=path_list)
            print(list_to_print)
        elif user_number_choice.__eq__('4'):
            user_string, tree_root, leaf_path = parse_user_path_input(user_string)
            print(merkle_tree.validate_proof_of_inclusion(hash256(user_string), tree_root, leaf_path))
        elif user_number_choice.__eq__('5'):
            generatePem()
        elif user_number_choice.__eq__('6'):
            raw = input()
            while raw:
                user_string +='\n'+raw
                raw = input()
            signRoot(user_string, merkle_tree.tree_root_calculate())
        elif user_number_choice.__eq__('7'):
            raw = input()
            pub_key = user_string
            while raw:
                pub_key +='\n'+raw
                raw = input()
            raw = input()
            raw = raw.split()
            verify(pub_key, raw[0], raw[1])
        elif user_number_choice.__eq__('8'):
            sparse_merkle_tree.add_leaf(user_string)
        elif user_number_choice.__eq__('9'):
            print(sparse_merkle_tree.tree_root_calculate())
        elif user_number_choice.__eq__('10'):
            print(sparse_merkle_tree.find_proof_of_inclusion(user_string))
        elif user_number_choice.__eq__('11'):
            user_string, value, leaf_path = parse_user_path_input(user_string)
            print(sparse_merkle_tree.validate_proof_of_inclusion(user_string, value, leaf_path))
        else:
            print("")
