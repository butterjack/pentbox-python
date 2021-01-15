import base64 ,hashlib
import pyinputplus as pyip
import string
import secrets
import pyfiglet

class Cryptographie:
	'''
		1- string to base_64
		2- string to multidigest(MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD-160)
		3- Hash Password Cracker (MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD-160)
		4- secure password generator
	'''
	methods = list(hashlib.algorithms_guaranteed)

	@classmethod
	def choose_method(cls):
		method = pyip.inputMenu(list(hashlib.algorithms_guaranteed))
		return method

	def base64_encoder(self,text):
		text_bytes = text.encode("ascii")
		base64_bytes = base64.b64encode(text_bytes)
		return base64_bytes

	@classmethod
	def text_to_hash(cls,text,method):
		encoded_text = text.encode()
		if(method.upper() == 'MD5'):
			return hashlib.md5(encoded_text).hexdigest()
		if(method.upper() == 'SHA1'):
			return hashlib.sha1(encoded_text).hexdigest()
		if(method.upper() == 'SHA256'):
			return hashlib.sha256(encoded_text).hexdigest()
		if(method.upper() == 'SHA384'):
			return hashlib.sha384(encoded_text).hexdigest()
		if(method.upper() == 'SHA512'):
			return hashlib.sha512(encoded_text).hexdigest()

	def multidigest(self , text):
		method = Cryptographie.choose_method()
		hash = Cryptographie.text_to_hash(text,method)
		return hash
	
	def password_cracker(self, hash, method, verbose= False):
		with open('pentbox-wlist.txt', 'r+') as f:
			passwords = f.read().splitlines()
		for password in passwords: 
			if( Cryptographie.text_to_hash(password,method) == hash ):
				return password

		return 'Sorry we didn\'t find the password'

	def generate_password(self):
		alphabet = string.ascii_letters + string.digits
		while True:
			password = ''.join(secrets.chouce(alphabet) for i in range(10))
			if (any(c.islower() for c in password)
					and any(c.isupper() for c in password)
					and sum(c.isdigit() for c in password) >= 3):
				break
		return password

	def menu(self):
		ascii_banner = pyfiglet.figlet_format("HASHAGE") 
        print(ascii_banner)


cryp = Cryptographie()
print(cryp.multidigest('mecca'))
hash = input('give your hash : ')
x = cryp.password_cracker(hash,'md5')
print(x)