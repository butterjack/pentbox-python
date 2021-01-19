import pyinputplus as pyip
import string
import pyfiglet
import stdiomask

import hashlib
import math
import os

from Crypto.Cipher import AES
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

class SymmetricEncryption:
	'''
		1- encrypt my message
        2- decrypt my message 
	'''
    
	@classmethod
	def encrypt(cls, method='AES'):
		plaintext = pyip.inputStr('enter data for encryption :  ')
		plaintext = str.encode(plaintext)

		key = stdiomask.getpass()
		key = str.encode(key)


		if(method=='AES'):
			if(len(key)<16):
				key = key + str.encode((16-len(key))*'a')
			elif(len(key)>16):
				key = key[:16]
			cipher = AES.new(key, AES.MODE_EAX)

			nonce = cipher.nonce
			ciphertext, tag = cipher.encrypt_and_digest(plaintext)

			print('nonce: \n'+ str(nonce), '\nciphertext: \n'+ str(ciphertext), '\ntag: \n'+ str(tag))
			return (nonce,ciphertext,tag)

		elif(method=='Salsa20'):
			if(len(key)<32):
				key = key + str.encode((32-len(key))*'a')
			elif(len(key)>32):
				key = key[:32]
			cipher = Salsa20.new(key=key)
			ciphertext = cipher.nonce + cipher.encrypt(plaintext)
			print('ciphertext: \n'+ str(ciphertext))
			return ciphertext

	@classmethod
	def decrypt(cls, nonce=None, ciphertext=None, tag=None, method='AES'):
		key = stdiomask.getpass()
		key = str.encode(key)

		if(method=='AES'):
			if(len(key)<16):
				key = key + str.encode((16-len(key))*'a')
			elif(len(key)>16):
				key = key[:16]
			cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
			plaintext = cipher.decrypt(ciphertext)
			try:
				cipher.verify(tag)
				print("\nThe message is authentic:", plaintext)
			except ValueError:
				print("Key incorrect or message corrupted")

		elif(method=='Salsa20'):
			if(len(key)<32):
				key = key + str.encode((32-len(key))*'a')
			elif(len(key)>32):
				key = key[:32]
			msg_nonce = ciphertext[:8]
			ciphertext = ciphertext[8:]
			try:
				cipher = Salsa20.new(key=key, nonce=msg_nonce)
				plaintext = cipher.decrypt(ciphertext)
				print("The message is authentic:", plaintext)
			except ValueError:
				print("Key incorrect or message corrupted")


	@classmethod
	def menu(cls):
		ascii_banner = pyfiglet.figlet_format("SYMMETRIC ENCRYPTION") 
		print(ascii_banner)

		while(True):
			print('\n')
			choice = pyip.inputMenu(['encryption', 'quit'])
			if(choice=='encryption'):
				method = pyip.inputMenu(['AES', 'Salsa20'])
				print(method)
				if(method=='AES'):
					nonce,ciphertext,tag = SymmetricEncryption.encrypt(method=method)
				else: 
					ciphertext = SymmetricEncryption.encrypt(method=method)
				
				print('\nFor decryption: ')
				decrypt = pyip.inputMenu(['yes','no'])
				if(decrypt=='no'):
					continue
				elif(method=='AES'):
					SymmetricEncryption.decrypt(nonce,ciphertext,tag,method)
				elif(method=='Salsa20'):
					SymmetricEncryption.decrypt(nonce=None,ciphertext=ciphertext,tag=None,method=method)
				

			else:
				return
				
