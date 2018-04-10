#!/usr/bin/env python
# Based on BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net)        #

import sys
from struct import unpack
from StringIO import StringIO
from time import strftime, gmtime, mktime
import cookielib

FLAG_NONE     = 0
FLAG_SECURE   = 1	
FLAG_HTTP     = 4
FLAG_BOTH 	  = FLAG_SECURE | FLAG_HTTP

def parse(binary_file):
	file_header=binary_file.read(4)                             #File Magic String:cook 

	if str(file_header)!='cook':
		raise ValueError("Not a Cookies.binarycookie file")
		
	num_pages=unpack('>i',binary_file.read(4))[0]               #Number of pages in the binary file: 4 bytes

	page_sizes=[]
	for np in range(num_pages):
		page_sizes.append(unpack('>i',binary_file.read(4))[0])  #Each page size: 4 bytes*number of pages
		
	pages=[]
	for ps in page_sizes:
		pages.append(binary_file.read(ps))                      #Grab individual pages and each page will contain >= one cookie
    	
	for page in pages:
		page=StringIO(page)                                     #Converts the string to a file. So that we can use read/write operations easily.
		page.read(4)                                            #page header: 4 bytes: Always 00000100
		num_cookies=unpack('<i',page.read(4))[0]                #Number of cookies in each page, first 4 bytes after the page header in every page.
		
		cookie_offsets=[]
		for nc in range(num_cookies):
			cookie_offsets.append(unpack('<i',page.read(4))[0]) #Every page contains >= one cookie. Fetch cookie starting point from page starting byte

		page.read(4)                                            #end of page header: Always 00000000

		cookie=''
		for offset in cookie_offsets:
			page.seek(offset)                                   #Move the page pointer to the cookie starting point
			cookiesize=unpack('<i',page.read(4))[0]             #fetch cookie size
			cookie=StringIO(page.read(cookiesize))              #read the complete cookie 
			
			cookie.read(4)                                      #unknown
			
			flags=unpack('<i',cookie.read(4))[0]                #Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
			cookie.read(4)                                      #unknown
			
			urloffset=unpack('<i',cookie.read(4))[0]            #cookie domain offset from cookie starting point
			nameoffset=unpack('<i',cookie.read(4))[0]           #cookie name offset from cookie starting point
			pathoffset=unpack('<i',cookie.read(4))[0]           #cookie path offset from cookie starting point
			valueoffset=unpack('<i',cookie.read(4))[0]          #cookie value offset from cookie starting point
			
			endofcookie=cookie.read(8)                          #end of cookie
			expiry_date_epoch= unpack('<d',cookie.read(8))[0]+978307200          #Expiry date is in Mac epoch format: Starts from 1/Jan/2001
			create_date_epoch=unpack('<d',cookie.read(8))[0]+978307200           #Cookies creation time
			
			cookie.seek(urloffset-4)                            #fetch domaain value from url offset
			url=''
			u=cookie.read(1)
			while unpack('<b',u)[0]!=0:
				url=url+str(u)
				u=cookie.read(1)
					
			cookie.seek(nameoffset-4)                           #fetch cookie name from name offset
			name=''
			n=cookie.read(1)
			while unpack('<b',n)[0]!=0:
				name=name+str(n)
				n=cookie.read(1)
					
			cookie.seek(pathoffset-4)                          #fetch cookie path from path offset
			path=''
			pa=cookie.read(1)
			while unpack('<b',pa)[0]!=0:
				path=path+str(pa)
				pa=cookie.read(1)
					
			cookie.seek(valueoffset-4)                         #fetch cookie value from value offset
			value=''
			va=cookie.read(1)
			while unpack('<b',va)[0]!=0:
				value=value+str(va)
				va=cookie.read(1)

			yield cookielib.Cookie(
				version=0, 
				name=name, 
				value=value, 
				expires=expiry_date_epoch, 
				port=None, 
				port_specified=False, 
				domain=url, 
				domain_specified=True, 
				domain_initial_dot=False, 
				path=path, 
				path_specified=True, 
				secure= flags in [FLAG_HTTP,FLAG_BOTH], 
				discard=False, 
				comment=None, 
				comment_url=None, 
				rest={'HttpOnly': flags in [FLAG_HTTP,FLAG_BOTH]}, 
				rfc2109=False)
				
	binary_file.close()

def dump_netscape(binary_file):
    cookies = cookielib.MozillaCookieJar()
    for x in parse(binary_file): 
        cookies.set_cookie(x)		
    cookies.save("cookies.txt", ignore_discard=True, ignore_expires=True)


if __name__ == "__main__":
	if len(sys.argv)!=2:
		print("\nUsage: Python BinaryCookieReader.py [Full path to Cookies.binarycookies file] \n")
		print("Example: Python BinaryCookieReader.py ~/Library/Cookies/Cookies.binarycookies")
	else:
		filename = sys.argv[1]
		try:
			binary_file=open(filename,'rb')
			dump_netscape(binary_file)
		except IOError as e:
			print('File Not Found :'+ filename)
