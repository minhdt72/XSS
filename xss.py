import argparse
import requests
import urllib.parse
import re

def get_method(url, params):
    print('[-] Method: GET')
    print(f'\t[+] url: {url}')
    print(f'\t[+] payload: {params}')
    url = url + params
    response = requests.get(url, params=params)
    count = 0
    if params in response.text:
        print("\t[+] Detected XSS ")
        count += 1
    print(f'[-]Detect {count} parameter contain XSS in {url} ')

def post_method(url, params):
    print('[-] Method: POST')
    print(f'\t[+] url: {url}')
    print(f'\t[+] payload: {params}')
    #_params = input('\t[+] input paramameter: ')
    #_data = {_params: params}
    datas = urllib.parse.parse_qs(str(params))
    script_text_list = []
    for key, value in datas.items():
        datas[key] = value[0]
        temp = value[0].lower()
        if re.search(r'script.*>.*<.*/.*script', temp) is not None:
            temp = re.findall(r'script.*>.*<.*/.*script', temp)[0]
            temp = re.sub(r'script.*>', '', temp)
            temp = re.sub(r'<.*/.*script', '', temp)
            script_text_list.append(temp)

    response = requests.post(url, data=datas).content.decode().lower()
    count = 0
    for script in script_text_list:
        payload = re.findall(r'<\s*script\s*>' + re.escape(script) + r'<\s*/\s*script\s*>', response)
        if len(payload) != 0:
            print("\t[+] Detected XSS ")
        count += 1
    print(f'[-]Detect {count} parameter contain XSS in {url} ')

if __name__ =="__main__":
    parser = argparse.ArgumentParser(description="option")
    parser.add_argument('-u', '--Url', type=str, help='url')
    parser.add_argument('-g', '--GET', type=str, help='Method GET')
    parser.add_argument('-p', '--POST', type=str, help='Method POST')
    args = parser.parse_args()

    if args.GET is not None:
        get_method(args.Url, params=args.GET)
    elif args.POST is not None:
        post_method(args.Url, params=args.POST)
