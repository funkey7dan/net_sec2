#Ben Eli, 319086435, Daniel Bronfman, 315901173
import hashlib
import math
import base64
import cryptography

done = False

class Node:

    def __init__(self,parent):
        self.leaf_id = 0
        self.left = None
        self.right = None
        self.parent = parent
    pass

class MerkleTree:
    def __init__(self):
        self.leaf_id = 0

    # on input of 1
    def add_leaf(self,input: str):
        """
       input : string until newline
       output :
       """
        self.leaf_id += 1
        pass

    # on input of 2
    def calc_root(self):
        """
        input :
        output : root value in hex
        """
        pass

    # on input of 3
    def generate_incl_proof(self,leaf_id):
        """
        input : X the number of the leaf - leftmost is 0
        output : root{space}hashX{space}...{space}hashY
        """
        pass

    # on input of 4
    def check_incl_proof(self,leaf_val):
        """
       input : string, the information represented by the leaf
       output : True if the proof is correct False otherwise
       """
        pass

    #on input of 5
    def generate_rsa_pair(self):
        """
        input:
        output: private key and public key
        """

    #on input of 6
    def generate_signature(self,sig_key):
        """
        input: signature key
        output: signature created by passed key
        """

    #on input of 7
    def verify_signature(self,ver_key,sig,to_ver):
        """
        input: verification key,signature,text to verify
        output: True if signature is correct, False otherwise
        """


if __name__ == '__main__':
    global done
    tree = None
    while True:
        tree = MerkleTree(0)
        #TODO: finish switch case
        switch = {0: exit(),1: tree.add_leaf(input = input()),2: tree.calc_root()}
        try:
            user_input = int(input())

            #wrapper loop
            pass
        except KeyboardInterrupt as e:
            print(e)
            break
    exit()
    print('PyCharm')
