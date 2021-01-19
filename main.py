import pyinputplus as pyip
import pyfiglet

from SymmetricEncryption import SymmetricEncryption
from AsymmetricEncryption import AsymmetricEncryption
from Encoding import Encoding
from Hashing import Hashing

import click

def menu():
    while(True):
        choice = pyip.inputMenu(['encoding','hashing','pwdCracker','symmetric-encrypt','asymmetric-encrypt','quit'])
        if(choice=='encoding'):
            Encoding.menu()
        elif(choice=='hashing'):
            Hashing.hash_menu()
        elif(choice=='pwdCracker'):
            Hashing.crack_menu()
        elif(choice=='symmetric-encrypt'):
            SymmetricEncryption.menu()
        elif(choice=='asymmetric-encrypt'):
            AsymmetricEncryption.menu()
        
        elif(choice=='quit'):
            return



@click.command()
@click.option('-m','--mode','mode', default='nothing' , help='choose the function to try')
def main(mode):
    """
        -----------------------------------------------------------------------
        --------------------------Security Project-----------------------------
        -----------------------------------------------------------------------
        The first menu does the following : encode and decode a given text to 
          various types of encoding utf8, ascii, base16, base32, base64        
        -----------------------------------------------------------------------
        The second menu does the following : hash a given text according to 
        various types of hashing MD5, SHA1, SHA256, SHA384, SHA512, SHA3_256,
        SHA3_384, SHAKE_128, SHA224, BLAKE2B, BLAKE2S, SHAKE_256, SHA3_512,
        SHA3_224                                                               
        -----------------------------------------------------------------------
        The third menu does the following: crack a given hashed password using 
        all the hashing functions mentioned above using a dictionary of 63175
        words under the name of pentbox-wlist.txt                              
        -----------------------------------------------------------------------
        The fourth menu does the following: encrypt a given message with an AES
        (Advanced Encryption Standard) or Salsa20 encryption which are symmetric
        encryption                                                                                                            
        -----------------------------------------------------------------------
        The last menu does the following: encrypt a given message with an RSA or
        Elgamal encryption which are asymmetric encryption                     
        -----------------------------------------------------------------------

    """
    if(mode=='symmetric'):
        SymmetricEncryption.menu()
    if(mode=='encoding'):
        Encoding.menu()
    if(mode=='hashing'):
        Hashing.hash_menu()
    if(mode=='crack'):
        Hashing.crack_menu()
    if(mode=='asymmetric'):
        AsymmetricEncryption.menu()


    if(mode=='nothing'):
        menu()


if __name__ == '__main__':
    main()