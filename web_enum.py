#!/usr/bin/python
from lxml import etree
import lxml.html
import socket
import ssl
import os
import sys
import pywebshot
import subprocess

ssl_scan = "/pentest/web/sslyze/sslyze.py" 
file = open('urls.txt', 'w')
csv = open('urls.csv', 'w')

def printHead(usage):
	print "------------------------------------------------------"
	print " HTTP Enumeration Script"
	print " Author: Meatballs"
	if usage:
		print " Usage: ./web_enum.py <nmap_xml>"
	print "------------------------------------------------------"

def writeCSVTitle(ip, port, protocol, html_file):
	try:
		title_doc = lxml.html.parse(html_file)
		title = title_doc.find(".//title").text
	except:
		title = ""
	csv.write(protocol + "," + ip + "," + port + "," + title + "\n")
	
def getOutput(ip, port, protocol, folder_created):

	if not folder_created:
		folder_created = 1
		if not os.path.exists(ip):
			os.makedirs(ip)
			
	port = str(port)
	ip = str(ip)
	address = ip + ":" + port
	file_name = ip + "_" + port
	uri = protocol + "://" + address
	
	output_img = protocol + "_" + file_name + ".png"
	output_response = ip + "/" + protocol + "_" + file_name + ".txt"
	output_html =  ip + "/" + protocol + "_" + file_name + ".html"
	
	response_cmd = "curl -s -i -m 2 -o " + output_response + " " + uri
	html_cmd = "curl -s -k -m 2 -o " + output_html + " " + uri
	html_file = os.getcwd() + "/" + output_html
	
	if protocol == "https":
		sslscan_cmd =  " --regular --xml_file " + ip + "/" + file_name + "_ssl_scan.xml " + address
		#devnull = open(os.devnull, 'w')
		#subprocess.Popen([sslscan_cmd, '/pentest/web/sslyze/'],stdout=devnull)
		#subprocess.call(["python", ssl_scan, sslscan_cmd])
			
	print "[+] Retrieving output for " + uri
	os.popen(response_cmd)
	os.popen(html_cmd)								
	pywebshot.take_screenshots(urls=[uri], path=ip) 
	file.write(uri + "\n")
	writeCSVTitle(ip, port, protocol, html_file)
	
usage = len(sys.argv) < 2
printHead(usage)

doc = etree.parse (sys.argv[1])
print "[+] Processing NMAP XML File: " + sys.argv[1]

for host in doc.getiterator('host'):

	ip = host.find('address').attrib["addr"]
	folder_created = 0
	
	for portObject in host.getiterator ('port'):
	
		if portObject.find('state').attrib["state"] == "open":
		
			if portObject.attrib["protocol"] == "tcp":
				port = int(portObject.attrib["portid"])
				service = portObject.find('service')
				if service.attrib["name"] == "http":
					protocol = "http"
					if "tunnel" in service.attrib:
						if service.attrib["tunnel"] == "ssl":
							protocol = "https"
					url = "{0}://{1}:{2}".format(protocol, ip, port)
					getOutput(ip, port, protocol, False)	
