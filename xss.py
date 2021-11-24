import argparse
import requests
import re
import urllib.parse

def get_method(url):
    print('[-] Method: GET')
    print(f'\t[+] url: {url}')
    count = 0
    payload = open('payload.txt', 'r')

    for pay in payload:
        target = url + pay
        response = requests.get(target).content.decode().lower()
        print(f'\t[+] payload: {pay}')

        if re.search(r'script.*>.*<.*/.*script', response):
            print("\t[*] Detected XSS ")
            count += 1
            break
        else:
            print("\t[--] Continue scanning")
            continue
    print(f'[-]Detect {count} param contain XSS in {url}')


def post_method(url, params):
    print('[-] Method: POST')
    print(f'\t[+] url: {url}')
    print(f'\t[+] Data: {params}')
    payload = open('payload.txt', 'r', encoding='UTF-8')
    count = 0

    data = urllib.parse.parse_qs(str(params))

    for pay in payload:
        key = list(data.keys())[0]
        print(f'\t[+] Parameter: {key}')
        data[key] = pay

        response = requests.post(url, data=data).content.decode().lower()

        if re.search(r'.*<.*script.*>.*<.*/.*script.*>.*', response):
            print(f"\t[+] payload: {pay}")
            print("\t[*] Detected XSS ")
            count += 1
            break
        else:
            print(f"\t[+] payload: {pay}")
            print("\t[--] Continue scanning")
            continue

    print(f'[-]Detect {count} param contain XSS in {url}')

if __name__ =="__main__":
    parser = argparse.ArgumentParser(description="option")
    parser.add_argument('-u', '--Url',  help='url')
    parser.add_argument('-g', '--GET',  help='Method GET', nargs='*')
    parser.add_argument('-p', '--POST', help='Method POST')
    args = parser.parse_args()

    if args.GET is not None:
        get_method(args.Url)
    elif args.POST is not None:
        post_method(args.Url, params=args.POST)
