import os
import re
from chepy import Chepy
from typing import List

# Sample 42ba370427c163b0f3fd56111b42841a8ab0a876e77425d480df143d6f32b1ea

directory = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
file_name = os.path.join(directory, 'malz')

def extract_base64(content: str) -> str:
    return re.findall(r'[a-zA-Z0-9+\/]{33,}={0,2}', content)[0]

def decode_malware(content: str) -> str:
    extracted_base64 = extract_base64(file_text)
    second_stage = Chepy(extracted_base64) \
        .base64_decode() \
        .decode_utf_16_le() \
        .o

    extracted_inner_base64 = extract_base64(second_stage)
    third_stage = Chepy(extracted_inner_base64) \
        .base64_decode() \
        .gzip_decompress() \
        .out_as_str()

    extracted_inner_inner_base64 = extract_base64(third_stage)

    return Chepy(extracted_inner_inner_base64) \
        .base64_decode() \
        .xor(23) \
        .bytearray_to_str() \
        .out_as_str()

def extract_iocs(shell_code: str) -> List[str]:
    user_agent = re.findall(r'User.*\)', shell_code)[0]
    ip_address = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', shell_code)[0]
    return user_agent, ip_address

if __name__ == "__main__":
    with open(file_name, 'r') as malz:
        file_text = malz.read()

        shell_code = decode_malware(file_text)
        user_agent, ip_address = extract_iocs(shell_code)

        print(f'\nUser_Agent: {user_agent}\nIP_Address: {ip_address}')