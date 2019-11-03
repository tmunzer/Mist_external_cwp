from django.shortcuts import render
import hmac
import base64
import hashlib
import urllib.parse
import jwt

from datetime import datetime
# Create your views here.


def make_digest(message, key):
    key = bytes(key, 'UTF-8')
    message = bytes(message, 'UTF-8')

    hashed = hmac.new(key, message, hashlib.sha1)

    sig = base64.b64encode(hashed.digest()).decode('utf-8')
    print(hashed)
    print(sig)
    # signature2 = base64.urlsafe_b64encode(bytes(signature1, 'UTF-8'))
    #signature2 = base64.urlsafe_b64encode(signature1)
    #print(signature2)

    return sig


def index(request):
    debug = False

    if debug: 
        ap_mac= "5c5b35001234"
        wlan_id= "be22bba7-8e22-e1cf-5185-b880816fe2cf"
        client_mac= "d58f6bb4c9d8"
        minutes= 480
        expires= 1768587994
        forward_url= "http://www.mist.com/"
        authorize_only= False
        api_secret = "test-secret"
        uri = "http://portal.mist.com/authorize-test"
        ap_name = "test ap"
        site_name = "test site"
    else:
        ap_mac = request.GET["ap_mac"]
        wlan_id = request.GET["wlan_id"]
        client_mac = request.GET["client_mac"]
        minutes = 1800
        now = datetime.now()
        expires =  str(int(datetime.timestamp(now)) + 60)
        if "url" is request.GET:
            forward_url = request.GET["url"]
        else:
            forward_url = "https://www.mist.com"
        ap_name = request.GET["ap_name"]
        site_name = request.GET["site_name"]
        authorize_only= False
        api_secret = "R2fgVhzsrvNl7lNnUbTFQJOoDC749AKyfC3kflrj"
        uri = "http://portal.mist.com/authorize"


    download_kbps = str(0)
    upload_kbps = str(0)
    quota_mbytes = str(0)

    ######## SIG
    token_string = wlan_id+"/"+ap_mac+"/"+client_mac+"/" + str(minutes) + "/"+download_kbps+"/"+upload_kbps+"/"+quota_mbytes

    final_forward_url = urllib.parse.quote(forward_url, safe='')
    
    encoded_token = base64.b64encode(token_string.encode("ascii"))
    final_token = urllib.parse.quote(encoded_token, safe='')

    signature = "expires="+str(expires)+"&token="+final_token+"&forward="+final_forward_url    
    encoded_signature = make_digest(signature, api_secret)
    final_signature = urllib.parse.quote(encoded_signature, safe='')

    auth_link_sig = uri+"?signature="+final_signature + "&expires="+str(expires)+"&token="+final_token + "&forward="+final_forward_url

    ####### JWT
    payload = {
    "ap_mac": ap_mac,
    "wlan_id": wlan_id,
    "client_mac": client_mac,
    "minutes": int(minutes),
    "expires": int(expires),
    "forward": forward_url,
    "authorize_only": authorize_only
    }

    jwt_token = jwt.encode(payload, api_secret, algorithm='HS256')
    jwt_encoded = urllib.parse.quote(jwt_token, safe='')

    auth_link_jwt = uri+"?jwt="+str(jwt_encoded)

    ####### RENDER

    context = {
        'wlan_id': wlan_id,
        'ap_mac': ap_mac,
        'client_mac': client_mac,
        'url': forward_url,
        'ap_name': ap_name,
        'site_name': site_name,
        'expires': expires,
        'auth_link_jwt': auth_link_jwt,
        'auth_link_sig': auth_link_sig
    }

    return render(request, 'debug/index.html', context)
