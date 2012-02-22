
from thread import start_new_thread
from module.network.HTTPRequest import BadHeader
from module.plugins.Hook import Hook

import urllib
import httplib
import mimetypes
import base64
import time

ANTIGATE_KEY = "111111111111111111111"

class AntiGateException(Exception):
    def __init__(self, err):
        self.err = err

    def getCode(self):
        return self.err

    def __str__(self):
        return "<AntiGateException %s>" % self.err

    def __repr__(self):
        return "<AntiGateException %s>" % self.err

class AntiGate(Hook):
    __name__ = "AntiGate"
    __version__ = "0.01"
    __description__ = """Send captchas to antigate.com. Using CaptchaTrader.py as example."""
    __config__ = [("activated", "bool", "Activated", True),
                  ("force", "bool", "Force CT even if client is connected", False),
                  ("apikey", "str", "API KEY", ""),]
    __author_name__ = ("LR")
    __author_mail__ = ("eternal.l.c.r@gmail.com")

    #SUBMIT_URL = "http://antigate.com/in.php"
    RESPOND_URL = "http://antigate.com/res.php"    



    def setup(self):
        self.info = {}
        
    def getCredits(self):
        params = urllib.urlencode({'key' : self.getConfig("apikey") , 'action' : 'getbalance'})
        f = urllib.urlopen(AntiGate.RESPOND_URL+'?%s' %params)
   
        self.info["credits"] = f.read()
        self.logInfo(_("%s credits left" % self.info["credits"]))
        return self.info["credits"]
	

    def get_content_type(self,filename):
      return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    
    def get_cap_text(self, cap_id):
        ''' Waiting and getting captcha text '''
        
        self.logInfo(_('--- Get captcha text'))
        time.sleep(5)

        params =  urllib.urlencode({'key' : self.getConfig("apikey") , 'action' : 'get', 'id' : cap_id})
        url =  AntiGate.RESPOND_URL+'?%s' %params
        while 1:
                res= urllib.urlopen(url).read()
                if res == 'CAPCHA_NOT_READY':
                        time.sleep(1)
                        continue
                break

        res= res.split('|')
        if len(res) == 2:
                return tuple(res)
        else:
                return ('ERROR', res[0])
	


    def send_cap(self, key, fn):
	''' sending captcha
		IN:
			key	- account key
			fn		- file name
		OUT:
			captcha id	- in case of success
			False	- in case of failure
	'''
	self.logInfo(_('--- Send captcha'))
	
	
	data = open(fn, 'rb').read()

	# data boundary
	boundary= '----------OmNaOmNaOmNamo'

	# building POST request
	body = '''--%s
Content-Disposition: form-data; name="method"

base64
--%s
Content-Disposition: form-data; name="key"

%s
--%s
Content-Disposition: form-data; name="body";
Content-Transfer-Encoding: base64
Content-Type: %s;charset=%s

%s
--%s
Content-Disposition: form-data; name="ext";

%s
--%s--

''' % (boundary, boundary, key, boundary, self.get_content_type(fn), 'utf-8', base64.b64encode(data).decode(), boundary, 'jpg',boundary)

	headers = {'Content-type' : 'multipart/form-data; boundary=%s' % boundary}
	# connecting
	h = httplib.HTTPConnection('antigate.com')
	# sending request
	h.request("POST", "/in.php", body, headers)
	# receiving answer and analyzing it
	resp = h.getresponse()
	data = resp.read()
	h.close()
	self.logInfo(_('Captcha : %s %s %s' % (resp.status, data, resp.reason)))
	if resp.status == 200:
		cap_id= int(data.split('|')[1])
		return cap_id
	else:
		self.logInfo(_('Captcha not send: %s %s' % (resp.status, resp.reason)))
		return False

    def submit(self, captcha, captchaType="file", match=None):
        if not ANTIGATE_KEY:
            raise AntiGateException("No API Key Specified!")

        #if type(captcha) == str and captchaType == "file":
        #    raise CaptchaTraderException("Invalid Type")
        assert captchaType in ("file", "url-jpg", "url-jpeg", "url-png", "url-bmp")
        
        api_key = self.getConfig("apikey")
        self.logInfo(_("api_key : %s" % api_key))
        self.logInfo(_("captcha : %s" % captcha))
        
        cap_id = self.send_cap(api_key, captcha)

        ticket,result = self.get_cap_text(cap_id)

        self.logDebug("result %s : %s" % (ticket,result))

        return ticket, result

    def respond(self, ticket, success):
        try:
            if success :
              params = urllib.urlencode({'key' : self.getConfig("apikey") , 'action' : 'reportbad', 'ticket' : ticket})
              f = urllib.urlopen(AntiGate.RESPOND_URL+'?%s' %params)
              response = f.read
              
        except BadHeader, e:
            self.logError(_("Could not send response."), str(e))

    def newCaptchaTask(self, task):
        if not task.isTextual():
            return False

        if not self.getConfig("apikey"):
            return False

        if self.core.isClientConnected() and not self.getConfig("force"):
            return False

        if self.getCredits() > 0.0010:
            task.handler.append(self)
            task.setWaiting(100)
            start_new_thread(self.processCaptcha, (task,))

        else:
            self.logInfo(_("Your AntiGate Account has not enough credits"))

    def captchaCorrect(self, task):
        if "ticket" in task.data:
            ticket = task.data["ticket"]
            self.respond(ticket, True)

    def captchaInvalid(self, task):
        if "ticket" in task.data:
            ticket = task.data["ticket"]
            self.respond(ticket, False)

    def processCaptcha(self, task):
        c = task.captchaFile
        try:
            ticket, result = self.submit(c)
        except AntiGateException, e:
            task.error = e.getCode()
            return

        task.data["ticket"] = ticket
        task.setResult(result)

