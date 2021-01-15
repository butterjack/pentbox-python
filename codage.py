import base64 ,hashlib
import string
import re

class Codage:

    def coder(self, CH):
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

    def decoder (self, cryp):
        res= ''
        arr = re.split('(\d+)', cryp)
        arr.pop(0)
        for i in range(0,len(arr)-1,2):
            res+=int(arr[i]) * arr[i+1]
        return res



codage = Codage()
word = input('Enter your word')
print (codage.coder(word))
print ( codage.decoder(codage.coder(word)))