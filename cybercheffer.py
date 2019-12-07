import os
import re
from chepy import Chepy

# Sample 42ba370427c163b0f3fd56111b42841a8ab0a876e77425d480df143d6f32b1ea

directory = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
file_name = os.path.join(directory, 'malz')


with open(file_name, 'r') as malz:
    whatever = malz.read()

    extracted_base64 = re.findall(r'[a-zA-Z0-9+\/]{33,}={0,2}', whatever)[0]
    second_stage = Chepy(extracted_base64).base64_decode().decode_utf_16_le().o

    extracted_inner_base64 = re.findall(r'[a-zA-Z0-9+\/]{33,}={0,2}', second_stage)[0]
    third_stage = Chepy(extracted_inner_base64).base64_decode().gzip_decompress().out_as_str()
    
    extracted_inner_inner_base64 = re.findall(r'[a-zA-Z0-9+\/]{33,}={0,2}', third_stage)[0]
    shell_code = str(Chepy(extracted_inner_inner_base64).base64_decode().xor(23).bytearray_to_str())
    
    
    user_agent = re.findall(r'User.*\)', shell_code)
    ip_address = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', shell_code)

    print(f'\nUser_Agent: {user_agent}\nIP_Address: {ip_address}')