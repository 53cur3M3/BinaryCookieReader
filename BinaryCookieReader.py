#*******************************************************************************
# BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net)        #
# Updated for Python 3                                                         #
#*******************************************************************************

import sys
from struct import unpack
from io import BytesIO
from time import strftime, gmtime

if len(sys.argv) != 2:
    print("\nUsage: Python BinaryCookieReader.py [Full path to Cookies.binarycookies file] \n")
    print("Example: Python BinaryCookieReader.py C:\\Cookies.binarycookies")
    sys.exit(0)

FilePath = sys.argv[1]

try:
    binary_file = open(FilePath, 'rb')
except IOError as e:
    print('File Not Found: ' + FilePath)
    sys.exit(0)

file_header = binary_file.read(4)  # File Magic String: cook

if file_header.decode() != 'cook':
    print("Not a Cookies.binarycookie file")
    sys.exit(0)

num_pages = unpack('>i', binary_file.read(4))[0]  # Number of pages in the binary file: 4 bytes

page_sizes = []
for _ in range(num_pages):
    page_sizes.append(unpack('>i', binary_file.read(4))[0])  # Each page size: 4 bytes * number of pages

pages = []
for ps in page_sizes:
    pages.append(binary_file.read(ps))  # Grab individual pages, each containing >= one cookie

for page in pages:
    page = BytesIO(page)  # Converts the bytes to a file-like object
    page.read(4)  # Page header: 4 bytes (Always 00000100)
    num_cookies = unpack('<i', page.read(4))[0]  # Number of cookies in the page

    cookie_offsets = []
    for _ in range(num_cookies):
        cookie_offsets.append(unpack('<i', page.read(4))[0])  # Each cookie's starting offset

    page.read(4)  # End of page header: Always 00000000

    for offset in cookie_offsets:
        page.seek(offset)  # Move pointer to the cookie's start
        cookiesize = unpack('<i', page.read(4))[0]  # Fetch cookie size
        cookie = BytesIO(page.read(cookiesize))  # Read the complete cookie

        cookie.read(4)  # Unknown

        flags = unpack('<i', cookie.read(4))[0]  # Cookie flags
        cookie_flags = ''
        if flags == 0:
            cookie_flags = ''
        elif flags == 1:
            cookie_flags = 'Secure'
        elif flags == 4:
            cookie_flags = 'HttpOnly'
        elif flags == 5:
            cookie_flags = 'Secure; HttpOnly'
        else:
            cookie_flags = 'Unknown'

        cookie.read(4)  # Unknown

        urloffset = unpack('<i', cookie.read(4))[0]  # Domain offset
        nameoffset = unpack('<i', cookie.read(4))[0]  # Name offset
        pathoffset = unpack('<i', cookie.read(4))[0]  # Path offset
        valueoffset = unpack('<i', cookie.read(4))[0]  # Value offset

        cookie.read(8)  # End of cookie

        expiry_date_epoch = unpack('<d', cookie.read(8))[0] + 978307200  # Expiry date in Mac epoch
        expiry_date = strftime("%a, %d %b %Y", gmtime(expiry_date_epoch))

        create_date_epoch = unpack('<d', cookie.read(8))[0] + 978307200  # Creation date in Mac epoch
        create_date = strftime("%a, %d %b %Y", gmtime(create_date_epoch))

        # Fetch domain
        cookie.seek(urloffset - 4)
        url = bytearray()
        while True:
            b = cookie.read(1)
            if b == b'\x00':  # Null-terminated string
                break
            url.extend(b)
        url = url.decode('utf-8')

        # Fetch name
        cookie.seek(nameoffset - 4)
        name = bytearray()
        while True:
            b = cookie.read(1)
            if b == b'\x00':
                break
            name.extend(b)
        name = name.decode('utf-8')

        # Fetch path
        cookie.seek(pathoffset - 4)
        path = bytearray()
        while True:
            b = cookie.read(1)
            if b == b'\x00':
                break
            path.extend(b)
        path = path.decode('utf-8')

        # Fetch value
        cookie.seek(valueoffset - 4)
        value = bytearray()
        while True:
            b = cookie.read(1)
            if b == b'\x00':
                break
            value.extend(b)
        value = value.decode('utf-8')

        print(f'Cookie: {name}={value}; domain={url}; path={path}; expires={expiry_date}; {cookie_flags}')

binary_file.close()

