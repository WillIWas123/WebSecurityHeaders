import sys
import json
import requests
import argparse
import os

import urllib3
urllib3.disable_warnings()

ERROR=0
REDIRECT_OFF_DOMAIN=1
REDIRECT_TO_HTTPS=2
NO_REDIRECT_TO_HTTPS=3
NO_REDIRECT=4
MISSING_CSP=5
MISSING_HSTS=6
MISSING_PERMISSIONS_POLICY=7
MISSING_REFERRER_POLICY=8

FINDINGS = {MISSING_CSP:"95800af8-5559-4335-9487-278bd653ddde/",MISSING_HSTS:"e9fc1558-7813-417d-aebe-0576098c2b61",MISSING_PERMISSIONS_POLICY:"ec67689c-0ecf-4437-97b8-b7f677147093",MISSING_REFERRER_POLICY:"94b62f3a-f521-4674-8430-686361117872",NO_REDIRECT_TO_HTTPS:"cd7e96cc-d6a8-4649-a471-fe0370ebd07f"}

def parse_request(args):
    if args.request:
        with open(args.request, "r") as f:
            lines = f.read().split("\n")
    elif args.raw_request:
        lines=args.raw_request.split("\n")
    method,path,version = lines[0].split() # Keeping version here for future reference when urllib starts supporting HTTP2

    headers = {}
    host = None
    body=None
    for c,line in enumerate(lines[1:]):
        if not line:
            body = "\n".join(lines[c+2:])
            break
        key,value = line.split(":")
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

def check_csp(resp): # TODO: expand to check whether the CSP is trash
    csp = resp.headers.get("Content-Security-Policy")
    return csp is not None

def check_hsts(resp):
    hsts = resp.headers.get("Strict-Transport-Security")
    return hsts is not None

def check_permissions_policy(resp): # TODO: expand to check whether policy is trash
    permissions_policy = resp.headers.get("Permissions-Policy")
    return permissions_policy is not None

def check_referrer_policy(resp):
    referrer_policy = resp.headers.get("Referrer-Policy")
    return referrer_policy is not None

def check_redirect(resp): # TODO: this may create false-positives if a similar redirection history occurs: domain -> off-domain -> domain
    domain = resp.history[0].request.headers.get("host")
    output = ""
    for i in resp.history:
        if i.status_code >= 300 and i.status_code < 400:
            location = i.headers.get("location","")
            if not location.startswith("https://"):
                if not location.startswith("http://{domain}"):
                    output = REDIRECT_OFF_DOMAIN # Still not redirecting to HTTPs, but redirecting off-domain
                else:
                    output = NO_REDIRECT_TO_HTTPS
            elif not location.startswith(f"https://{domain}"): # TODO: can be bypassed by redirecting to https://{domain}.domain.com
                output = REDIRECT_OFF_DOMAIN
            else:
                output = REDIRECT_TO_HTTPS
    return output

def report_to_sysreptor(project_id,token,finding_id,url):

    headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"}
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
        data = {"template":finding["template"],"template_language":"en-US"}
        resp = requests.post(rurl,data=data,headers=headers,verify=False)
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
    parser.add_argument("--request",type=str,help="Specify file to read with request")
    parser.add_argument("--raw-request",type=str,help="Specify raw request as argument")
    parser.add_argument("--url",type=str,help="Specify URL to check for issues")
    parser.add_argument("--timeout",type=float,default=10.0,help="Specify number of seconds before a timeout occurs")
    parser.add_argument("--http",action="store_true",help="Use HTTP instead of HTTPs")
    parser.add_argument("--verify",action="store_true",help="Verify SSL for requests made")
    parser.add_argument("--project-id",type=str,required=True,help="Specify project id for sysreptor project")
    args = parser.parse_args()

    token = None
    with open(os.path.expanduser("~")+"/.sysreptor/config.yaml","r") as f:
        data=f.read().split("\n")
    for i in data:
        if i.startswith("token:"):
            token = i.split("token:")[1].strip()
            break
    if token is None:
        print("Please add a sysreptor config at ~/.sysreptor/config.yaml!")
        sys.exit(1)

    if args.request or args.raw_request:
        method,headers,body,url = parse_request(args)
    elif args.url:
        method="GET"
        headers={}
        body=None
        url=args.url
    else:
        print("Please specify either --request, --raw-request or --url")
        sys.exit(1)

    if url.split(":")[0].strip() == "https":
        try:
            http_resp = requests.request(method,url.replace("https://","http://"),headers=headers,timeout=10.0,verify=False)
            if len(http_resp.history) == 0:
                output = NO_REDIRECT 
            else:
                output = check_redirect(http_resp)

        except Exception as e:
            output = ERROR

        if output == NO_REDIRECT or output == NO_REDIRECT_TO_HTTPS:
            report_to_sysreptor(args.project_id,token,NO_REDIRECT_TO_HTTPS,url.replace("https://","http://"))


    try:
        resp=requests.request(method,url,headers=headers,timeout=args.timeout,verify=args.verify)
        if len(resp.history) == 0:
            output = NO_REDIRECT
        else:
            output = check_redirect(resp)
        has_csp = check_csp(resp)
        if has_csp is False and (output == NO_REDIRECT or output == REDIRECT_TO_HTTPS):
            report_to_sysreptor(args.project_id,token,MISSING_CSP,url)
        has_hsts = check_hsts(resp)
        if has_hsts is False:
            report_to_sysreptor(args.project_id,token,MISSING_HSTS,url)
        has_permissions_policy = check_permissions_policy(resp)
        if has_permissions_policy is False and (output == NO_REDIRECT or output == REDIRECT_TO_HTTPS):
            report_to_sysreptor(args.project_id,token,MISSING_PERMISSIONS_POLICY,url)
        has_referrer_policy = check_referrer_policy(resp)
        if has_referrer_policy is False and (output == NO_REDIRECT or output == REDIRECT_TO_HTTPS):
            report_to_sysreptor(args.project_id,token,MISSING_REFERRER_POLICY,url)
    except Exception as e:
        pass

if __name__ == "__main__":
    main()
