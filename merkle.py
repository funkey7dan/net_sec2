# Ben Eli, 319086435, Daniel Bronfman, 315901173
# -*- coding: utf-8 -*-
import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import math
import base64


# hash function on a given string


def sha256_from_str(string):
    return (hashlib.sha256((string.encode("utf-8")))).hexdigest()


def get_key_from_input(inputs):
    i = 1
    user_input = ""
    while "-----END" not in user_input:
        user_input += inputs[i] + "\n"
        i += 1
    return user_input


class Node:

    def __init__(self, data=None, left=None, right=None, sibling=None, is_left=None):
        self._parent = None
        self._left = left
        self._right = right
        self._data = data
        self._sibling = sibling
        self._is_left = is_left

    @property
    def is_left(self):
        return self._is_left

    @is_left.setter
    def is_left(self, value):
        self._is_left = value

    @property
    def left(self):
        return self._left

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
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
    def data(self, value):
        self._data = value

    @sibling.setter
    def sibling(self, value):
        self._sibling = value

    @left.setter
    def left(self, value):
        self._left = value

    @right.setter
    def right(self, value):
        self._right = value


class MerkleTree:

    def __init__(self):
        self._leaf_id = 0
        self._root = Node(None)
        self._values = []

    def recursive_build(self, values):
        temp = []
        if len(values) <= 1:
            return values[0]
        while len(values) >= 1:
            if len(values) == 1:
                temp_node = (Node(data=values[0].data, left=values[0]))
                values[0]._parent = temp_node
                temp_node._sibling = temp[-1]
                temp.append(temp_node)
                values = values[1:]
            else:
                values[0]._sibling = values[1]
                values[1]._sibling = values[0]
                values[0].is_left = True
                values[1].is_left = False
                temp_node = Node(data=sha256_from_str(values[0].data + values[1].data), left=values[0],
                                 right=values[1])
                values[0]._parent = temp_node
                values[1]._parent = temp_node
                temp.append(temp_node)
                values = values[2:]
        return self.recursive_build(temp)

    def generate_tree(self):
        self._root = self.recursive_build(self._values)

    # on input of 1
    def add_leaf(self, leaf_data: str):
        """
       input : string until newline
       output :
       """
        self._values.append(Node(data=sha256_from_str(leaf_data)))
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

    def generate_helper(self, leaf_id):
        proof = ""
        next_node = self._values[int(leaf_id)]
        if next_node.sibling is not None:
            if next_node.sibling.is_left and next_node.sibling.is_left is not None:
                proof = proof + " 0" + next_node.sibling.data
            if not next_node.sibling.is_left and next_node.sibling.is_left is not None:
                proof = proof + " 1" + next_node.sibling.data
        while next_node.parent != self._root:
            if next_node.parent.sibling is not None:
                next_node = next_node.parent.sibling
                if next_node.is_left and next_node.is_left is not None:
                    proof = proof + " 0" + next_node.data
                if not next_node.is_left and next_node.is_left is not None:
                    proof = proof + " 1" + next_node.data
        return proof

    # on input of 3
    def generate_incl_proof(self, leaf_id):
        """
        input : X the number of the leaf - leftmost is 0
        output : root{space}hashX{space}...{space}hashY
        """
        print(self._root.data + self.generate_helper(leaf_id))

    # on input of 4
    def check_incl_proof(self, leaf_val, proof):
        """
       input : string, the information represented by the leaf
       output : True if the proof is correct False otherwise
       """
        hash_list = proof.split()
        leaf_hashed_input = sha256_from_str(leaf_val)
        result = leaf_hashed_input
        for i in range(1, len(hash_list)):
            if (hash_list[i])[0] == '1':
                result += hash_list[i][1:]
            else:
                result = hash_list[i][1:] + result;
            result = sha256_from_str(result)
        if result == hash_list[0]:
            print("True")
            return
        print("False")

    # on input of 5
    def generate_rsa_pair(self):
        """
        input:
        output: private key and public key
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption())
        pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

        print((pem_private).decode())
        print((pem_public).decode())

    # on input of 6
    def generate_signature(self, sig_key):
        """
        input: signature key
        output: signature created by passed key
        """
        if self._root == None:
            print("")
            return
        message = self._root.data.encode()
        private_key = serialization.load_pem_private_key(sig_key.encode(), password=None, )
        signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        # print(base64.b64decode(signature).decode('ascii'))
        print(signature.hex())

    # on input of 7
    def verify_signature(self, ver_key, sig, to_ver):
        """
        input: verification key,signature,text to verify
        output: True if signature is correct, False otherwise
        """
        # ver_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1MAmLr5TwN8OnQF9OjfWGyGuHfl5056u7XBjYcsidkQHVLkK8NhFzSvBnQbi18PcXVSLusLPVnGs6a9rfN9NkCM6uSom0+lpFgMWuD/7w0HPIW7Cw0hVlFNWvZ8vv5uzA/mzpF8S1fRmCMkfQyP4TDJ2MImQxcdkWDpFDq1pmvRJweavzUnc2eUmuz4bwLYwv3CBKDlCSdIAFCkVP6PJl8cbZkOPqbVPMW+MLf+pZrKfWczCxCnzHmLbzngClQp+4meAtGOGgKKwsmS1eA0BAYfao0g+cu1ESU5ePea/jrX0nJONvDOAeh00keQvxE1xoEnKppbKT2F6RTyBITbCmwIDAQABAoIBAH0iQ5MMyVBRIlRAsvpSKzGsHrBsszZASF1J1HqJs0xiePlhGUlNu8iQqwGEMlp8ThnrB4Ci4rbSh8SvNAavhPx5bCnK3CmaSP/0cyGOKLPQ+laMwiuAWS2z0voXLkuB9copzXqpnPeRF46lVSj1eC7BI3krAKcDv0aRh1q5rrq/T3sH76nENwjxRVig9wZ1jWNBqpWD7LOx2M8INcW4ZbcALbREzKEyydZ1BBx0FXMYyeJRvRdmLzNCb7RZ/wz4B/1bSoUUi8mTBF6xft6fZ6JQNak9r2PEvc7eh+FWoDF3Gu3PBFb0poX7SdWWle9qG6efTSiavUo+cetSQb0qV4kCgYEA+weJpApGEqxKwCe8oN+pd42QOmnKEzqQlZ33pSP97VmOQj6GcXfuonnH/0hu4jozj5N96kOCDjDPdpCOvUgzupJBhiRr1M/4y8f+SoWrRCuHHscnfh5Qpv+iwpSHTcV8ys2fGowpmd9tZfGerJkvAcD/3jG1Mo+0anemHAoCbXUCgYEA2PaTrBVXKJovd9ZjPqWX7MWhTh1NFGCquQPe4cX5h8wIgjSBqozsosKzKYHmK/kw7yU/P9UvCiEbiowPiqDZoSbZ6twpf2bcXjaVKWdRqFD+OvGXEvpPVvdbRUXv0J9UDsd1EDM5/lX6Sja54ibIKP+okcjH3YPd4xbRvZoyHc8CgYARJgGsGBuTWPu+RrinEMBl72DD7MgmKiEIZ4MsX9oP5cdHFThf9f5yUPltoggZIjq1ezDl2PjAeWsiwVtO6OjHvQgG3uQS5KYtXZssghciEAsp+hbjkbSWw+3ddwILOQt+Wy+cQ6jv3wh9J1VcmxZP+1w/VIv5SUHc6BGL5s8lpQKBgQC4zfdlOdw+0m6iZfOtNgHdhU1rqxuvwtNIutpLd4WfvRR2S+Ey88zQqoVPUr1LMXwUB6cDaUQjHaZG8hx+2ZnmYaB3I8cZJPWKLnYJiV8Nvsd+T7B+UsXn7tRIglTOYBiKaiz1epzoXjXOpyTYVG5kNbhRTTOpJJyIxTQsiz4rEwKBgBxxJ6t4F8APkYkXaY5EB/Z6EtJJDbKgoqBkfWuVZ0DzPBmVKUbP6EKMT085EM/HlQer1QQjfkdepVuCL7mdDjKcxVMiuMKPWtVlsJjtJMa11smmdqZ5UT/w6R54/knAIkDXNlGE2xBXCcfKdhF2+lICi5COWEQk5NASSVdgfKjN\n-----END RSA PRIVATE KEY-----"

        # sig = "LhnptHJUc4M0GVZR+wbp5NC6owLwH2+N/UpOKV6jnyH8iA8YoVSQkMU63z8QZyr50L1f4hTWSxZbjzeQ1Rm/1OyAyX9QdQHIrMWRjOx0GPfqPi4wmcmF9ZxPr7ShwRZtbqz9mAekKYDell44Pj21xKsFFy4PgpnxrXFNppPOA3ZpQk245bYPIdzYpcmq0FyYx5RQQCQYBV69QrQOAvvkVVkwZbiqI0/+tZWmfNdV/x6E3PWYljSccMLW/m4nhcy+XQ39Q2oxIzYlobwndW3epxEReLzP7qeN9BR/BVew2yCn4quhm1fA7544mpZaW0VynQDRHBy7gqJDhuWRLjKOcQ=="
        # to_ver = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bc"
        public_key = serialization.load_pem_public_key(ver_key.encode())
        sig.replace('\n','')
        return public_key.verify(
            base64.b64encode(sig.encode('ascii')),
            to_ver.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


def main(tree):
    user_choice = None
    user_input = None
    # TODO: finish switch case
    user_choice = input()
    inputs = user_choice.split()
    if (len(inputs) > 0):

        match inputs[0]:
            case '0':
                exit()
            case '1':
                user_input = inputs[1]
                tree.add_leaf(leaf_data=user_input)
            case '2':
                tree.calc_root()
            case '3':
                user_input = inputs[1]
                tree.generate_incl_proof(leaf_id=user_input)
            case '4':
                user_input1 = inputs[1]
                user_input2 = ""
                for x in range(2, len(inputs)):
                    user_input2 += inputs[x]
                    user_input2 += " "
                tree.check_incl_proof(leaf_val=user_input1, proof=user_input2)
            case '5':
                tree.generate_rsa_pair()
            case '6':
                user_input = " ".join(inputs[1:])+ "\n"
                while "-----END" not in user_input:
                    user_input += input() + "\n"
                user_input = user_input[0:-1]
                tree.generate_signature(sig_key=user_input)
            case '7':
                user_input1 = " ".join(inputs[1:]) + "\n"
                while "-----END" not in user_input1:
                    user_input1 +=input()+ "\n"
                user_input1=user_input1[0:-1]
                input()
                second_input=input()
                second_input=second_input.split()
                user_input2 = second_input[0]
                user_input3 = second_input[1]
                tree.verify_signature(ver_key=user_input1, sig=user_input2, to_ver=user_input3)
            case "\n":
                return


if __name__ == '__main__':
    try:
        tree = MerkleTree()
        while True:
            main(tree)
    except KeyboardInterrupt as e:
        print(e)
