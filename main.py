from fastapi import FastAPI
import requests

# To run on server - uvicorn main:app --reload

app = FastAPI()

classes={
'A':{

'network_bits':7,

'host_bits':24

},

'B':{

'network_bits':14,

'host_bits':16

},

'C':{

'network_bits':21,

'host_bits':8

},

'D':{

'network_bits':'N/A',

'host_bits':'N/A'

},

'E':{

'network_bits':'N/A',

'host_bits':'N/A'

},

}


######################


@app.get("/ipcalc")
async def ipcalc():
    output = {}
    newHeaders = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    response = requests.post('https://httpbin.org/post',
                             data={"address": "136.206.18.7"},
                             headers=newHeaders)

    response_Json = response.json()
    ip = response_Json['data'][8:]

    # Check the class of the ip address by calling the convert_to_bin method.
    # By converting to binary, you can check the first bits of the ip address to find out the class
    if convert_to_bin(ip)[0][0:1] == "0":
        output["Class"] = "A"
    elif convert_to_bin(ip)[0][0:2] == "10":
        output["Class"] = "B"
    elif convert_to_bin(ip)[0][0:2] == "11":
        output["Class"] = "C"
    elif convert_to_bin(ip)[0][0:3] == "111":
        output["Class"] = "D"
    else:
        output["Class"] = "E"

    # Check what class the ip address is
    # Can find the number of networks by doing 2 to the power of network bits
    # The network bits are found in the classes dictionary
    if output["Class"] == "A":
        output["num_networks"] = 2 ** classes["A"]["network_bits"]
    elif output["Class"] == "B":
        output["num_networks"] = 2 ** classes["B"]["network_bits"]
    elif output["Class"] == "C":
        output["num_networks"] = 2 ** classes["C"]["network_bits"]
    else:
        output["num_networks"] = "N/A"

    # Check what class the ip address is
    # Can find the number of hosts by doing 2 to the power of hosts bits
    # The host bits are found in the classes dictionary
    if output["Class"] == "A":
        output["num_hosts"] = 2 ** classes["A"]["host_bits"]
    elif output["Class"] == "B":
        output["num_hosts"] = 2 ** classes["B"]["host_bits"]
    elif output["Class"] == "C":
        output["num_hosts"] = 2 ** classes["C"]["host_bits"]
    # For class D and E, no answer for number of hosts and number of networks
    else:
        output["num_hosts"] = "N/A"

    # First, check the class of the ip address
    # Can then get the first and last address after finding out the class
    if output["Class"] == "A":
        output["first_address"] = "0.0.0.0"
        output["last_address"] = "127.255.255.255"
    elif output["Class"] == "B":
        output["first_address"] = "128.0.0.0"
        output["last_address"] = "191.255.255.255"
    elif output["Class"] == "C":
        output["first_address"] = "192.0.0.0 "
        output["last_address"] = "223.255.255.255"
    elif output["Class"] == "D":
        output["first_address"] = "224.0.0.0"
        output["last_address"] = "239.255.255.255"
    elif output["Class"] == "E":
        output["first_address"] = "240.0.0.0"
        output["last_address"] = "255.255.255.255"

    return output

######################

@app.get("/subnet")
async def subnet():
    output={}
    newHeaders = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post('https://httpbin.org/post',
                             data={
                                 "address": "192.168.10.0",
                                 "mask": "255.255.255.192"
                             },
                             headers=newHeaders)

    response_Json = response.json()
    address = response_Json['data'][8:20]
    m=response_Json['data'][26:]

    ip=convert_to_bin(address)
    mask=convert_to_bin(m)

    cidr_num = cidr_not(mask)
    output["address_cidr"] = address + "/" + str(cidr_num)

    host_bits=mask[-1]

    # Iterate through last byte in subnet mask to count up zero and one bits
    one_bits=0
    zero_bits=0
    for i in host_bits:
        if i == "1":
            one_bits+=1
        elif i == "0":
            zero_bits+=1

    #2 to the power of the number of one bits is equal to the number of subnets
    output["num_subnets"] = 2**one_bits
    #2 to the power of the number of zero bits minus 2 (network address and broadcast address) is equal to the addressable hosts
    output["addressable_hosts_per_subnet"] = (2 ** zero_bits) - 2

    # Split string IP address into list
    # Split subnet mask into list
    # 256 - the last byte in the subnet mask
    # Make last byte in IP address '0' - this will be the first valid subnet
    # Make last byte of IP addresses equal to last byte + (256 - last byte in the subnet mask)
    # Change the last byte to a string
    # Add this string to the string version of the IP address
    # Appened this new IP to the list of Valid Subnets
    validSubnets = []
    i = -1
    ip = address.split(".")
    blocksList = m.split(".")
    blocks = 256 - int(blocksList[i])
    ip[i] = '0'
    newIP = '.'.join(ip)
    validSubnets.append(newIP)
    ip[i] = 0
    for block in range(output["num_subnets"] - 1):
        ip[i] += blocks
        ip[i] = str(ip[i])
        newIP = '.'.join(ip)
        ip[i] = int(ip[i])
        validSubnets.append(newIP)

    output["valid_subnets"] = validSubnets
    output["broadcast_addresses"] = get_broadcasts(validSubnets)
    output["first_addresses"] = get_firstAddress(validSubnets)
    output["last_addresses"] = get_lastAddress(validSubnets)

    return output

######################

@app.get("/supernet")
async def supernet():
    output={}

    newHeaders = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    response = requests.post('https://httpbin.org/post',
                             data={"addresses":["205.100.0.0","205.100.1.0","205.100.2.0","205.100.3.0"]},
                             headers=newHeaders)
    addresses=[]

    response_Json = response.json()
    input = response_Json['data'].split('&')
    for ip in input:
        #Append just the string IP to addresses without the 'address' key
        addresses.append(ip[10:])

    # Convert each IP to binary list
    # Use .join() to join the list of bytes into a string
    first = ''.join(convert_to_bin(addresses[0]))
    second = ''.join(convert_to_bin(addresses[1]))
    third = ''.join(convert_to_bin(addresses[2]))
    fourth = ''.join(convert_to_bin(addresses[3]))

    # Iterate through each binary IP address from input
    # This allows you to find the common prefix of the binary addresses to find network mask
    # While each bit is equivalent, increment count by 1
    count=0
    i=0
    while first[i] == second[i] == third[i] == fourth[i]:
        count+=1
        i+=1

    cidr="{}/{}".format(addresses[0], count)
    output["address"] = cidr

    mask = "1" * count + first[count:]
    maskList = []
    for i in range(4):
        maskList.append(mask[:8])
        mask = mask[8:]

    output["mask"] = convert_to_decimal(maskList)

    return output


def get_broadcasts(subnets):
    """
        Calculates a list of braodcast addresses for each subnet
        :param subnets: An array containing 4 ip addresses
        each represented as a string. The ip addresses are the valid subnets
        eg. ["192.168.10.0","192.168.10.64","192.168.10.128","192.168.10.192"]
        :return broadcasts: An array containing 4 ip addresses
        each represented as a string. The ip addresses are the broadcast addresses
        eg. ["192.168.10.63","192.168.10.127","192.168.10.191","192.168.10.255"]
    """
        # For each ip string in the list, split each byte of the ip into a list
        # Add this list of bytes to a new list 'tmp'
        # Pop off the last element of the list of bytes and call it last
        # Add 63 to the int version of the string byte and call it last_n
        # Append the string version of last_n to the list of bytes
        # Create new list called broadcasts and append each list of bytes to it
        # Call '.'.join() to make the list of bytes a string again

    tmp = []
    for ip in subnets:
        ip = ip.split(".")
        tmp.append(ip)
        last = ip.pop()
        last_n = int(last) + 63
        ip.append(str(last_n))

    broadcasts = []
    for item in tmp:
        broadcasts.append('.'.join(item))

    return broadcasts

def get_firstAddress(subnets):
    """
        Calculates a list of ip addresses as strings that represent the network addresses of a subnet
        :param subnets: An array containing 4 ip addresses
        each represented as a string. The ip addresses are the valid subnets
        eg. ["192.168.10.0","192.168.10.64","192.168.10.128","192.168.10.192"]
        :return: An array containing 4 ip addresses
        each represented as a string. The ip addresses are the network addresses (first addresses of the subnet)
    """
    # For each ip string in the list, split each byte of the ip into a list
    # Add this list of bytes to a new list 'tmp'
    # Pop off the last element of the list of bytes and call it last
    # Add 1 to the int version of the string byte and call it last_n
    # Append the string version of last_n to the list of bytes
    # Create new list called first_addr and append each list of bytes to it
    # Call '.'.join() to make the list of bytes a string again

    tmp = []
    for ip in subnets:
        ip = ip.split(".")
        tmp.append(ip)
        last = ip.pop()
        last_n = int(last) + 1
        ip.append(str(last_n))

    first_addr = []
    for item in tmp:
        first_addr.append('.'.join(item))

    return first_addr

def get_lastAddress(subnets):
    """
        Calculates a list of ip addresses as strings that represent the last addresses of a subnet
        :param subnets: An array containing 4 ip addresses
        each represented as a string. The ip addresses are the valid subnets
        eg. ["192.168.10.0","192.168.10.64","192.168.10.128","192.168.10.192"]
        :return: An array containing 4 ip addresses
        each represented as a string. The ip addresses are the last addresses of the subnet
    """
    # For each ip string in the list, split each byte of the ip into a list
    # Add this list of bytes to a new list 'tmp'
    # Pop off the last element of the list of bytes and call it last
    # Add 62 to the integer version of the string byte and call it last_n
    # Append the string version of last_n to the list of bytes
    # Create new list called last_addr and append each list of bytes to it
    # Call '.'.join() to make the list of bytes a string again

    tmp = []
    for ip in subnets:
        ip = ip.split(".")
        tmp.append(ip)
        last = ip.pop()
        last_n = int(last) + 62
        ip.append(str(last_n))

    last_addr = []
    for item in tmp:
        last_addr.append('.'.join(item))

    return last_addr


def cidr_not(mask):
    """
    Take in an array of four strings representing the bytes of a subnet mask
    Calculates the CIDR number
    :param mask: An array containing the subnet mask of an IP address in binary
    :return cidr: The CIDR number for the IP address in the subnet endpoint
    """
    # Iterate through each of the 4 strings representing the bytes of subnet mask
    # If the bit is a 1, increment the CIDR number
    # The look will check every bit in the subnet mask and then return the CIDR number
    # Used for the subnet endpoint

    cidr=0
    for byte in mask:
        for bit in byte:
            if bit == "1":
                cidr+=1

    return cidr

def convert_to_bin(ip):
    """
    	Converts an ip address in decimal dot notation
    	represented as a string into a list of
    	four binary strings
    	each representing one byte of the address
    	:param ip: The ip address as a string in decimal dot notation
    	e.g. "132.206.19.7"
    	:return: An array of four binary strings each representing one byte
    	of ip e.g.
    	['10000100', '11001110', '00010011', '00000111']
    """
    # Split IP into an array
    # For each number in it convert to an integer
    # Format the integer as binary
    # Return an array

    return [format(int(x), '08b') for x in ip.split('.')]

def convert_to_decimal(ip_addr_list):
	"""
	Take in an array of four strings represting the bytes of an ip address
	and convert it back into decimal dot notation
	:param ip_addr_list: An array of four binary strings each
	representing one byte of ip_addr e.g. ['10000100', '11001110',
	'00010011', '00000111']
	:return: The ip address as a string in decimal dot notation e.g.
	'132.206.19.7'
	"""
	# for each string in the list
	# use str(int(x,2)) to convert it into a decimal number
	# and then turn that number into a string e.g. '10000100' -> '132'
	# put all converted numbers into a list ["132","206","19","7"]
	# call ".".join on the list to merge them into a string separated by "."
	return ".".join([str(int(x,2)) for x in ip_addr_list])
