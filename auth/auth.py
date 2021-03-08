import requests
import urllib3
from requests.auth import HTTPBasicAuth
from getpass import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def basicAuth(fmcIP, user, passwd):
    api_uri = "/api/fmc_platform/v1/auth/generatetoken"
    url = "https://" + fmcIP + api_uri
    response = requests.request("POST", url, verify=False, auth=HTTPBasicAuth(user, passwd))
    accesstoken = response.headers["X-auth-access-token"]
    refreshtoken = response.headers["X-auth-refresh-token"]
    DOMAIN_UUID = response.headers["DOMAIN_UUID"]

    return [accesstoken,refreshtoken,DOMAIN_UUID]