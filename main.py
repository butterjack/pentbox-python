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