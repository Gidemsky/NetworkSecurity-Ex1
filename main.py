from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class MerkleTree:

    def __init__(self):
        """
        size - the numbers of leaf in the tree
        also it initiate the tree as empty in the begin
        """
        self.hash_tree = {}
        self.size = 0
        # self.initiate_tree()  # create empty mht

    def add_leaf(self, leaf_data):
        """
        add lead to the tree and hash the data
        :param leaf_data: the data to add and to hash
        :return:
        """
        hash_leaf = hash256(leaf_data)
        self.size += 1
        # store the hashed lead as tree node in the following format:
        # (i , i+1)
        self.save_node(self.size - 1, self.size, hash_leaf)

    def merkle_tree_calculation(self, l_index, r_index):
        """
        calculate recursively the nodes and create new one in case it doesn't exist
        :param l_index:
        :param r_index:
        :return: the node number (l_index , r_index)
        """
        try:
            merkle_node = self.get_node(l_index, r_index)
        except KeyError:  # no stored node, so make one TODO: maybe change more
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
            proof_path = self.rec_find_proof_of_inclusion(node_to_proof, left, k) + [("1" + self.merkle_tree_calculation(k, right)), ]
        else:
            proof_path = self.rec_find_proof_of_inclusion(node_to_proof, k, right) + [("0" + self.merkle_tree_calculation(left, k)), ]
        return proof_path

    def find_proof_of_inclusion(self, node_to_proof):
        """
        returns a list of hashed value
        :param node_to_proof: the node we look for to prove it contains to the tree
        :return: the path proof
        """
        return self.rec_find_proof_of_inclusion(node_to_proof, 0, self.size)

    def validate_proof_of_inclusion(self, leaf_hash, root_hash, proof_of_inclusion):
        """
        checks if the proof of inclusion to leaf is true or not
        :param leaf_hash: the leaf to check if the path is true
        :param root_hash: the tree root
        :param proof_of_inclusion: the path
        :return: true or false
        """
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
        if self.size > 0:
            return self.merkle_tree_calculation(0, self.size)
        else:
            return hash('')

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
    root, path = user_in.split(sep=" ", maxsplit=1)
    return root, path

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
    print(f"{private_pem}\n{public_pem}")

def signRoot(key,mktree):
    pass

if __name__ == '__main__':

    merkle_tree = MerkleTree()

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
            user_input = input()
            tree_root, leaf_path = parse_user_path_input(user_input)
            print(merkle_tree.validate_proof_of_inclusion(hash256(user_string), tree_root, leaf_path))
        elif user_number_choice.__eq__('5'):
            generatePem()
        elif user_number_choice.__eq__('5'):
            signRoot('key',)
        elif user_number_choice.__eq__('exit'):
            print("bye bye! ")
            break
