
# 0 - Legitimate
# 1 - Phishing
# 2 - Suspicious

# importing required packages
import pandas as pd
import requests
from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime

cd = None
class FeatureExtraction:
   def __init__(self):
        pass

    # 1. Domain of the URL (Domain) 
   def getDomain(self, url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
            return domain

    # 2. Checks for IP address in URL (Have_IP)

    # If the domain part of URL has IP address, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).

   def havingIP(self, url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip


    # 3.Checks the presence of @ in URL (Have_At)

   def have_At_Sign(self, url):
    if "@" in url:
        at = 1    
    else:
        at = 0    
    return at


    # 4. Finding the length of URL and categorizing (URL_Length)

   def getLength(self, url):
    if len(url) < 54:
        length = 0          # legitimate
    elif len(url) >= 54 and len(url) <= 75:
        return 2            # suspicious
    else:
        length = 1          # phishing  
    return length


    # 5. Checking for redirection '//' in the url (Redirection)

   def redirection(self, url):
    if "//" in urlparse(url).path:
        return 1            # phishing
    else:
        return 0            # legitimate
    #   pos = url.rfind('//')
    #   if pos > 6:
    #     if pos > 7:
    #       return 1
    #     else:
    #       return 0
    #   else:
    #     return 0

    # 6. Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)

   def httpDomain(self, url):
        match=re.search('https://|http://',url)
        try:
            if match.start(0)==0 and match.start(0) is not None:
                url=url[match.end(0):]
                match=re.search('http|https',url)
                if match:
                    return 1
                else:
                    return 0
        except:
            return 1
    #   domain = urlparse(url).netloc
    #   if 'https' in domain:
    #     return 1
    #   else:
    #     return 0


    # 7. Checking for Shortening Services in URL (Tiny_URL)

    # shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
    #                       r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
    #                       r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
    #                       r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
    #                       r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
    #                       r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
    #                       r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
    #                       r"tr\.im|link\.zip\.net"

   def tinyURL(self, url):
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return 1               # phishing
        else:
            return 0               # legitimate
        
        # match=re.search(shortening_services,url)
        # if match:
        #     return 1
        # else:
        #     return 0


    # 8. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)

   def prefixSuffix(self, url):
        if '-' in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate
        
   def dns_record(self, url):
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        #print(domain_name)
    except:
        dns = 1
        
    if dns == 1:
        return 1
    else:
        return 0


    # 10. Web traffic (Web_Traffic)

   def web_traffic(self, url):
    try:
        #Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except TypeError:
            return 1
    if rank <100000:
        return 1
    else:
        return 0


    # 11. Survival time of domain: The difference between termination time and creation time (Domain_Age)  

   def domainAge(self, url):
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    if dns == 1:
        return 1
    else:
       creation_date = domain_name.creation_date
       expiration_date = domain_name.expiration_date
       if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
        try:
            creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
            return 1
       if ((expiration_date is None) or (creation_date is None)):
            return 1
       elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
       else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
              age = 1
            else:
              age = 0
       return age

    # 12. End time of domain: The difference between termination time and current time (Domain_End) 

   def domainEnd(self, url):
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
    
    if dns == 1:
       return 1
    else:
       expiration_date = domain_name.expiration_date
       if isinstance(expiration_date,str):
        try:
            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
            return 1
       if (expiration_date is None):
            return 1
       elif (type(expiration_date) is list):
            return 1
       else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if ((end/30) < 6):
              end = 0
            else:
              end = 1
       return end


    # 13. IFrame Redirection (iFrame)

   def iframe(self, url):
    response = requests.get(url)
    if response == "":
        return 1
    else:
        if re.findall(r"[|]", response.text):
            return 0
        else:
            return 1

    # 14. Checks the effect of mouse over on status bar (Mouse_Over)

   def mouseOver(self, url):
    response = requests.get(url)
    if response == "" :
        return 1
    else:
        if re.findall("", response.text):
          return 1
        else:
          return 0

    # 15. Checks the status of the right click attribute (Right_Click)

   def rightClick(self, url):
    response = requests.get(url)
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
          return 0
        else:
          return 1
        

    # 16. Checks the number of forwardings (Web_Forwards)

   def forwarding(self, url):
    response = requests.get(url)
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
          return 0
        else:
          return 1
    

# ### Computing URL Function

def getAttributes(url):

  fe = FeatureExtraction()
  havingIP = fe.havingIP(url)
  have_At_Sign = fe.have_At_Sign(url)
  getLength = fe.getLength(url)
  redirection = fe.redirection(url)
  httpDomain = fe.httpDomain(url)
  tinyURL = fe.tinyURL(url)
  prefixSuffix = fe.prefixSuffix(url)
  dns = fe.dns_record(url)
  domainAge = fe.domainAge(url)
  domainEnd = fe.domainEnd(url)
  iframe = fe.iframe(url)
  mouseOver = fe.mouseOver(url)
  rightClick = fe.rightClick(url)
  forwarding = fe.forwarding(url)

  data_col = {
     'Have_IP': pd.Series(havingIP),
     'Have_At': pd.Series(have_At_Sign),
     'URL_Length': pd.Series(getLength),
     'Redirection': pd.Series(redirection),
     'https_Domain': pd.Series(httpDomain),
     'TinyURL': pd.Series(tinyURL),
     'Prefix/Suffix': pd.Series(prefixSuffix),
     'DNS_Record': pd.Series(dns),
     'Domain_Age': pd.Series(domainAge),
     'Domain_End': pd.Series(domainEnd),
     'iFrame': pd.Series(iframe),
     'Mouse_Over': pd.Series(mouseOver),
     'Right_Click': pd.Series(rightClick),
     'Web_Forwards': pd.Series(forwarding)
  }

  data = pd.DataFrame(data_col)
  print(data.columns)
  return data

  #Address bar based features (8)

#   features.append(getDomain(url))
#   features.append(havingIP(url))
#   features.append(have_At_Sign(url))
#   features.append(getLength(url))
#   features.append(redirection(url))
#   features.append(httpDomain(url))
#   features.append(tinyURL(url))
#   features.append(prefixSuffix(url))
  
#   #Domain based features (3)

#   dns = 0
#   try:
#     domain_name = whois.whois(urlparse(url).netloc)
#   except:
#     dns = 1

#   features.append(dns)
#   # features.append(web_traffic(url))
#   features.append(1 if dns == 1 else domainAge(domain_name))
#   features.append(1 if dns == 1 else domainEnd(domain_name))

#   # HTML & Javascript based features (4)
  
#   try:
#     response = requests.get(url)
#   except:
#     response = ""
#   features.append(iframe(response))
#   features.append(mouseOver(response))
#   features.append(rightClick(response))
#   features.append(forwarding(response))


#   feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'Redirection', 
#                       'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 
#                       'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']

#   features = pd.DataFrame(features, columns=feature_names)
#   print(features.columns)
#   return features

