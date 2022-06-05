#Ben Eli, 319086435, Daniel Bronfman, 315901173
import hashlib
import math
import base64
import cryptography

done = False

class Node:

    def __init__(self):
        self.id = 0

    pass

class MerkleTree:
    def __init__(self):
        pass

    # on input of 1
    def add_leaf(self,input: str):
        """
       input : string until newline
       output :
       """
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
    while not done:
        try:
            #wrapper loop
            pass
        except KeyboardInterrupt as e:
            print(e)
            break
    exit()
    print('PyCharm')
