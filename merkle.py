#Ben Eli, 319086435, Daniel Bronfman, 315901173
# -*- coding: utf-8 -*-
import hashlib

from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend
import math
import base64

#hash function on a given string
def sha256_from_str(string):
    return (hashlib.sha256((string.encode("utf-8")))).hexdigest()

class Node:

    def __init__(self,data = None,left = None,right = None,sibling = None):
        self._parent = None
        self._left = left
        self._right = right
        self._data = data
        self._sibling = sibling

    @property
    def left(self):
        return self._left

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self,value):
        self._parent = value

    @property
    def sibling(self):
        return self._sibling

    @property
    def right(self):
        return self._right

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self,value):
        self._data = value

    @sibling.setter
    def sibling(self,value):
        self._sibling = value

    @left.setter
    def left(self,value):
        self._left = value

    @right.setter
    def right(self,value):
        self._right = value

class MerkleTree:

    def __init__(self):
        self._leaf_id = 0
        self._root = Node(None)
        self._values = []

    def recursive_build(self,values):
        temp = []
        if len(values) <= 1:
            return values[0]
        while len(values) >= 1:
            if len(values) == 1:
                temp_node = (Node(data = values[0].data,left = values[0]))
                values[0]._parent = temp_node
                temp_node._sibling = temp[-1]
                temp.append(temp_node)
                values = values[1:]
            else:
                values[0]._sibling = values[1]
                values[1]._sibling = values[0]
                temp_node = Node(data = sha256_from_str(values[0].data + values[1].data),left = values[0],
                                 right = values[1])
                values[0]._parent = temp_node
                values[1]._parent = temp_node
                temp.append(temp_node)
                values = values[2:]
        return self.recursive_build(temp)

    def generate_tree(self):
        self._root = self.recursive_build(self._values)

    # on input of 1
    def add_leaf(self,leaf_data: str):
        """
       input : string until newline
       output :
       """
        self._values.append(Node(data = sha256_from_str(leaf_data)))
        self.generate_tree()

    # on input of 2
    def calc_root(self):
        """
        input :
        output : root value in hex
        """
        if self._root.data is None:
            print("")
            return
        print(self._root.data)

    def generate_helper(self,leaf_id):
        proof = ""
        next_node = self._values[int(leaf_id)]
        if next_node.sibling is not None:
            proof += next_node.sibling.data
        while next_node.parent != self._root:
            if next_node.parent.sibling is not None:
                next_node = next_node.parent.sibling
                proof = proof + " " + next_node.data
        return proof

    # on input of 3
    def generate_incl_proof(self,leaf_id):
        """
        input : X the number of the leaf - leftmost is 0
        output : root{space}hashX{space}...{space}hashY
        """
        print(self._root.data + " " + self.generate_helper(leaf_id))

    # on input of 4
    def check_incl_proof(self,leaf_val,proof):
        """
       input : string, the information represented by the leaf
       output : True if the proof is correct False otherwise
       """
        hash_list = proof.split()
        leaf_hashed_input = sha256_from_str(leaf_val)
        result = leaf_hashed_input
        for i in range(1,len(hash_list)):
            result += hash_list[i]
            result = sha256_from_str(result)
        if result == hash_list[0]:
            print("True")
            return
        print("False")

    #on input of 5
    def generate_rsa_pair(self):
        """
        input:
        output: private key and public key
        """
        private_key = rsa.generate_private_key(public_exponent = 65537,key_size = 2048,backend = default_backend())
        public_key = private_key.public_key()
        pem_private = private_key.private_bytes(encoding = serialization.Encoding.PEM,
                                                format = serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm = serialization.NoEncryption())
        pem_public = public_key.public_bytes(encoding = serialization.Encoding.PEM,
                                             format = serialization.PublicFormat.SubjectPublicKeyInfo)

        print((pem_private).decode())
        print((pem_public).decode())

    #on input of 6
    def generate_signature(self,sig_key):
        """
        input: signature key
        output: signature created by passed key
        """
        if self._root == None:
            print("")
            return
        message = self._root.data.encode()
        private_key = serialization.load_pem_private_key(sig_key.encode(),password = None,)
        signature = private_key.sign(message,padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
                                                         salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
        print(signature.hex())

    #on input of 7
    def verify_signature(self,ver_key,sig,to_ver):
        """
        input: verification key,signature,text to verify
        output: True if signature is correct, False otherwise
        """

def main(tree):
    user_choice = None
    user_input = None
    #TODO: finish switch case
    user_choice = input()
    user_choice = int(user_choice)
    match user_choice:
        case 0:
            exit()
        case 1:
            user_input = input()
            tree.add_leaf(leaf_data = user_input)
        case 2:
            tree.calc_root()
        case 3:
            user_input = input()
            tree.generate_incl_proof(leaf_id = user_input)
        case 4:
            user_input1 = input()
            user_input2 = input()
            tree.check_incl_proof(leaf_val = user_input1,proof = user_input2)
        case 5:
            tree.generate_rsa_pair()
        case 6:
            user_input = input() +"\n"
            while "-----END RSA PRIVATE KEY-----" not in user_input:
                user_input += input() + "\n"
            tree.generate_signature(sig_key = user_input)
        case 7:
            user_input1 = input()
            user_input2 = input()
            user_input3 = input()
            tree.verify_signature(ver_key = user_input1,sig = user_input2,to_ver = user_input3)
        case _:
            return

if __name__ == '__main__':
    try:
        tree = MerkleTree()
        while True:
            main(tree)
    except KeyboardInterrupt as e:
        print(e)
