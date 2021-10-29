import argparse
import requests
import urllib.parse
import re

header={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21'}
def get_method (url, params):
    print('[+] Method: GET')
    print(f'\t[+] url: {url}')
    print(f'\t[+] parameter: {params}')
    script_text_list = re.findall(r'script.*>.*<.*/.*script', str(params).lower())
    script_text_list = script_text_list + re.findall(r'script.*%3e.*%3c.*/.*script', str(params).lower())
    _params = urllib.parse.parse_qs(str(params))
    for key, value in _params.items():
        _params[key] = value[0]
    # lay doan script ben trong the script
    for i in range(0, len(script_text_list)):
        script_text_list[i] = re.sub(r'script.*>', '', script_text_list[i])
        script_text_list[i] = re.sub(r'<.*/.*script', '', script_text_list[i])
        script_text_list[i] = re.sub(r'script.*%3e', '', script_text_list[i])
        script_text_list[i] = re.sub(r'%3c.*/.*script', '', script_text_list[i])
    url = url + '?' + params
    content = requests.get(url, params=_params, headers=header).content.decode().lower()
    count = 0
    for script in script_text_list:
        if re.search(r'<\s*script\s*>' + re.escape(script) + r'<\s*/\s*script\s*>', content) is not None:
            print("\t[+] Detected XSS ")
            count += 1
    print(f'Detect {count} parameter contain XSS in {url} ')

def post_method(url, params):
    print('[+] Method: POST')
    print(f'\t[+] url: {url}')
    print(f'\t[+] parameter: {params}')
    _data = urllib.parse.parse_qs(str(params))

    # tim doan xss trong cac tham so
    script_text_list = []
    for key, value in _data.items():
        _data[key] = value[0]
        temp = value[0].lower()
        if re.search(r'script.*>.*<.*/.*script', temp) is not None:
            temp = re.findall(r'script.*>.*<.*/.*script', temp)[0]
            temp = re.sub(r'script.*>', '', temp)
            temp = re.sub(r'<.*/.*script', '', temp)
            script_text_list.append(temp)
        if re.search(r'script.*%3e.*%3c.*/.*script', temp) is not None:
            temp = re.findall(r'script.*%3e.*%3ac.*/.*script', temp)[0]
            temp = re.sub(r'script.*%3e', '', temp)
            temp = re.sub(r'%3c.*/.*script', '', temp)
            script_text_list.append(temp)
    content = requests.post(url, headers=header, data=_data).content.decode().lower()
    count = 0
    for script in script_text_list:
        match = re.findall(r'<\s*script\s*>' + re.escape(script) + r'<\s*/\s*script\s*>', content)
        if len(match) != 0:
            print("\t[+] Detected XSS ")
            count += 1
    print(f'Detect {count} parameter contain XSS in {url} ')

if __name__ =="__main__":
    parser = argparse.ArgumentParser(description="option")
    parser.add_argument('-u', '--Url', help='url', type=str)
    parser.add_argument('-g', '--GET', type=str, help='Method GET')
    parser.add_argument('-p', '--POST', type=str, help='Method POST')
    args = parser.parse_args()
    if args.GET is not None:
        get_method(args.Url, params=args.GET)
    elif args.POST is not None:
        post_method(args.Url, params=args.POST)
