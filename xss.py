import argparse
import requests
import urllib.parse
import re

def get_method(url,params):
    print('[-] Method: GET')
    print(f'\t[+] url: {url}')
    print(f'\t[+] payload: {params}')
    url = url + params
    response = requests.get(url, params=params)
    count = 0
    if params in response.text:
        print("\t[+] Detected XSS ")
        count += 1
    print(f'[-]Detect {count} param contain XSS in {url} ')

def post_method(url,params):
    print('[-] Method: POST')
    print(f'\t[+] url: {url}')
    print(f'\t[+] data: {params}')
    payload_list = []
    data = urllib.parse.parse_qs(str(params))

    for key, value in data.items():
        data[key] = value[0]
        val = value[0].lower()
        if re.search(r'script.*>.*<.*/.*script', val) is not None:
            val = re.findall(r'script.*>.*<.*/.*script', val)[0]
            payload_list.append(val)

    response = requests.post(url, data=data).content.decode().lower()
    count = 0

    for payload in payload_list:
        if payload in response:
            print("\t[+] Detected XSS ")
            count += 1
    print(f'[-]Detect {count} param contain XSS in {url} ')

if __name__ =="__main__":
    parser = argparse.ArgumentParser(description="option")
    parser.add_argument('-u', '--Url',  help='url')
    parser.add_argument('-g', '--GET',  help='Method GET')
    parser.add_argument('-p', '--POST', help='Method POST')
    args = parser.parse_args()

    if args.GET is not None:
        get_method(args.Url, params=args.GET)
        
    elif args.POST is not None:
        post_method(args.Url, params=args.POST)
