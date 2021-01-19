import base64 ,hashlib
import string
import re
import pyfiglet
import pyinputplus as pyip

class Encoding:
	'''
		1- encode my message
		2- decode my message
	'''

	@classmethod
	def customEncoder(cls, CH):
		res = ''
		if len(CH) <= 50:
			cpt = 1
			for i in range(len(CH)-1):
				if CH[i] == CH[i+1]:
					cpt += 1
				else:
					res += str(cpt)+CH[i]
					cpt = 1
			res += str(cpt)+CH[-1]
		return res

	@classmethod
	def customDecoder (cls, cryp):
		res= ''
		arr = re.split('(\d+)', cryp)
		arr.pop(0)
		for i in range(0,len(arr)-1,2):
			res+=int(arr[i]) * arr[i+1]
		return res

	@classmethod
	def encode(cls,data, method):
		if(method in ['utf8','ascii']):
			encoded_text = str.encode(data,encoding=method)
			print('your encoded text is : ')
			print(encoded_text)
			return(encoded_text)
		
		elif(method == 'base64'):
			message_bytes = data.encode('ascii')
			base64_bytes = base64.b64encode(message_bytes)
			base64_message = base64_bytes.decode('ascii')
			print('your encoded text is : ' + base64_message)
			return(base64_message)
		
		elif(method == 'base32'):
			message_bytes = data.encode('ascii')
			base32_bytes = base64.b32encode(message_bytes)
			base32_message = base32_bytes.decode('ascii')
			print('your encoded text is : ' + base32_message)
			return(base32_message)
			
		elif(method=='base16'):
			message_bytes = data.encode('ascii')
			base16_bytes = base64.b32encode(message_bytes)
			base16_message = base16_bytes.decode('ascii')
			print('your encoded text is : ' + base16_message)
			return(base16_message)

		elif(method=='custom'):
			encoded_text = Encoding.customEncoder(data)
			print('your encoded text is : ' + encoded_text)
			return(encoded_text)

	@classmethod
	def decode(cls, encoded_data, method):
		if(method in ['utf8','ascii']):
			data = encoded_data.decode(encoding=method)
			print('your decoded text is : ' + data)
			return(data)
		
		elif(method == 'base64'):
			message_bytes = encoded_data.encode('ascii')
			base64_bytes = base64.b64decode(message_bytes)
			base64_message = base64_bytes.decode('ascii')
			print('your decoded text is : ' + base64_message)
			return(base64_message)
		
		elif(method == 'base32'):
			message_bytes = encoded_data.encode('ascii')
			base32_bytes = base64.b32decode(message_bytes)
			base32_message = base32_bytes.decode('ascii')
			print('your decoded text is : ' + base32_message)
			return(base32_message)
			
		elif(method=='base16'):
			message_bytes = encoded_data.encode('ascii')
			base16_bytes = base64.b32decode(message_bytes)
			base16_message = base16_bytes.decode('ascii')
			print('your decoded text is : ' + base16_message)
			return(base16_message)

		elif(method=='custom'):
			encoded_text = Encoding.customDecoder(encoded_data)
			return(encoded_text)


	

	@classmethod
	def menu(cls):
		ascii_banner = pyfiglet.figlet_format("ENCODING") 
		print(ascii_banner)

		while(True):
			print('\n')
			choice = pyip.inputMenu(['encode', 'quit'])
			if(choice=='encode'):
				data = pyip.inputStr('Please the texte to encode : \n')
				method = pyip.inputMenu(['utf8', 'ascii', 'base16', 'base32', 'base64', 'custom'])
				encoded_data = Encoding.encode(data,method)

				print('\nFor decoding : ')
				decode = pyip.inputMenu(['yes','no'])
				if(decode=='no'):
					continue
				else :
					Encoding.decode(encoded_data , method)
			
			else:
				return
