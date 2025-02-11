import sys
import json
import requests
import argparse
import os

import urllib3
import yaml

urllib3.disable_warnings()

ERROR = 0
REDIRECT_OFF_DOMAIN = 1
REDIRECT_TO_HTTPS = 2
NO_REDIRECT_TO_HTTPS = 3
NO_REDIRECT = 4
MISSING_CSP = 5
MISSING_HSTS = 6
MISSING_PERMISSIONS_POLICY = 7
MISSING_REFERRER_POLICY = 8

FINDINGS = {
    MISSING_CSP: "95800af8-5559-4335-9487-278bd653ddde",
    MISSING_HSTS: "e9fc1558-7813-417d-aebe-0576098c2b61",
    MISSING_PERMISSIONS_POLICY: "ec67689c-0ecf-4437-97b8-b7f677147093",
    MISSING_REFERRER_POLICY: "94b62f3a-f521-4674-8430-686361117872",
    NO_REDIRECT_TO_HTTPS: "cd7e96cc-d6a8-4649-a471-fe0370ebd07f"
    }


def parse_request(args):
    if args.request:
        with open(args.request, "r") as f:
            lines = f.read().split("\n")
    elif args.raw_request:
        lines=args.raw_request.split("\n")
    
    # Keeping version here for future reference when urllib starts supporting HTTP2
    method, path, version = lines[0].split() 

    headers = {}
    host = None
    body = None
    for c, line in enumerate(lines[1:]):
        if not line:
            body = "\n".join(lines[c+2:])
            break
        key,value = line.split(":", 1)
        if key.strip().lower() == "host":
            host = value.strip()
            continue # Don't add Host header to the headers, this will cause issues
        headers[key.strip()] = value.strip()
    if not host:
        print("Need to specify a Host header!")
        sys.exit(1)

    scheme = "https"
    if args.http:
        scheme = "http"
    url = f"{scheme}://{host}{path}"
    return method,headers,body,url


def has_csp(headers: dict) -> bool:
    # TODO: expand to check whether the CSP is trash
    return headers.get("Content-Security-Policy") is not None


def has_hsts(headers: dict) -> bool:
    return headers.get("Strict-Transport-Security") is not None


def has_permissions_policy(headers: dict) -> bool: 
    # TODO: expand to check whether policy is trash
    return headers.get("Permissions-Policy") is not None


def has_referrer_policy(headers: dict) -> bool:
    return headers.get("Referrer-Policy") is not None


def check_redirect(history: list) -> int: 
    # TODO: this may create false-positives if a similar redirection history occurs: domain -> off-domain -> domain
    domain = history[0].request.headers.get("host")
    output = ""
    for i in history:
        if i.status_code >= 300 and i.status_code < 400:
            location = i.headers.get("location", "")
            
            if not location.startswith("https://"):
                if not location.startswith("http://{domain}"):
                    # Still not redirecting to HTTPs, but redirecting off-domain
                    return REDIRECT_OFF_DOMAIN 
                else:
                    return NO_REDIRECT_TO_HTTPS
            # TODO: can be bypassed by redirecting to https://{domain}.domain.com
            elif not location.startswith(f"https://{domain}"): 
                return REDIRECT_OFF_DOMAIN
            else:
                return REDIRECT_TO_HTTPS


def report_to_sysreptor(project_id, token, finding_id, url):
    headers = {"Authorization":f"Bearer {token}","Content-Type":"application/json"}
    finding = FINDINGS[finding_id]

    # Checking if a finding already exists
    rurl = f"https://sysreptor.netsecurityrt.com/api/v1/pentestprojects/{project_id}/findings"
    resp = requests.get(rurl,headers=headers,verify=False)
    if resp.status_code > 400:
        print("Does not seem to be properly authenticated to Sysreptor!")
        sys.exit(1)
    data = resp.json()
    finding_id = None
    components = set() # Using a set to remove duplicates, if ordering is important this has to be re-designed
    for find in data:
        if find["template"] == finding:
            finding_id = find["id"]
            components = set(find["data"]["affected_components"])
            break

    if finding_id is None:
        # Creating new finding
        rurl = f"https://sysreptor.netsecurityrt.com/api/v1/pentestprojects/{project_id}/findings/fromtemplate/"
        data = {"template":finding,"template_language":"en-US"}
        resp = requests.post(rurl,data=json.dumps(data),headers=headers,verify=False)
        if resp.status_code > 400:
            print("Does not seem to be properly authenticated to Sysreptor!")
            sys.exit(1)
        data = resp.json()
        finding_id = data["id"]

    # Updating affected components
    rurl = f"https://sysreptor.netsecurityrt.com/api/v1/pentestprojects/{project_id}/findings/{finding_id}/"
    components.add(url)
    data = {"data":{"affected_components":list(components)}}
    resp = requests.put(rurl,data=json.dumps(data),headers=headers,verify=False)
    data = resp.json()
    print(f"Fixed finding for {data['data']['title']} for {url}")


def main():
    parser = argparse.ArgumentParser(description="WebSecurity Headers checks")
    parser.add_argument("--request", "-r", type=str, help="Specify file to read with request")
    parser.add_argument("--raw-request", type=str, help="Specify raw request as argument")
    parser.add_argument("--url", "-u", type=str, help="Specify URL to check for issues")
    parser.add_argument("--timeout", "-t", type=float, default=10.0, help="Specify number of seconds before a timeout occurs")
    parser.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPs")
    parser.add_argument("--verify", action="store_true", help="Verify SSL for requests made")
    parser.add_argument("--project-id", "-i", type=str, required=True, help="Specify project id for sysreptor project")
    args = parser.parse_args()

    token = None
    config_path = os.path.expanduser("~/.sysreptor/config.yaml")
    
    if not os.path.isfile(config_path):
        print("[!] File not found: ~/.sysreptor/config.yaml")
        sys.exit(1)
    
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        token = config.get("token")
        if not token:
            print("[!] \"token\" is missing from your Sysreptor config")
            sys.exit(1)

    if args.request or args.raw_request:
        method, headers, body, url = parse_request(args)
    elif args.url:
        method, headers, body, url = "GET", {}, None, args.url
    else:
        print("Please specify either --request, --raw-request or --url")
        sys.exit(1)

    if url.lower().startswith("https://"):
        try:
            insecure_url = url.replace("https://", "http://")
            http_resp = requests.request(method, insecure_url, headers=headers, timeout=10.0, verify=False)
            
            output = check_redirect(http_resp.history) if http_resp.history else NO_REDIRECT

        except Exception as e:
            output = ERROR

        if output in {NO_REDIRECT, NO_REDIRECT_TO_HTTPS}:
            report_to_sysreptor(args.project_id, token, NO_REDIRECT_TO_HTTPS, insecure_url)

    # TODO: keep try except around the HTTP request only
    try: 
        resp = requests.request(method, url, headers=headers, timeout=args.timeout, verify=args.verify)
        output = check_redirect(resp.history) if resp.history else NO_REDIRECT

        if not has_csp(resp.headers) and output in {NO_REDIRECT, REDIRECT_TO_HTTPS}:
            report_to_sysreptor(args.project_id, token, MISSING_CSP, url)

        if not has_hsts(resp.headers):
            report_to_sysreptor(args.project_id, token, MISSING_HSTS, url)

        if not has_permissions_policy(resp.headers) and output in {NO_REDIRECT, REDIRECT_TO_HTTPS}:
            report_to_sysreptor(args.project_id, token, MISSING_PERMISSIONS_POLICY, url)

        if not has_referrer_policy(resp.headers) and output in {NO_REDIRECT, REDIRECT_TO_HTTPS}:
            report_to_sysreptor(args.project_id, token, MISSING_REFERRER_POLICY, url)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
