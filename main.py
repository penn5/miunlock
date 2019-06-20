import logging, hashlib
from request import Auth, UnlockRequest

logging.basicConfig(level=logging.DEBUG)

RO_PRODUCT="cepheus"

auth = Auth()
auth.login_tui("unlockApi")
logging.debug(auth.__dict__)

r = UnlockRequest(auth, "unlock.update.miui.com", "/api/v3/unlock/userinfo", {
  "data":{
    "uid":auth.userid,
    "clientId":"1",
    "clientVersion":"3.3.827.31",
    "language":"en",
    "pcId":hashlib.md5(auth.pcid.encode("utf-8")).hexdigest(),
    "region":"",
}

})
r.add_nonce()
logging.debug(r.run())

r = UnlockRequest(auth, "unlock.update.miui.com", "/api/v2/unlock/device/clear", {
  "appId":"1",
  "data":{
    "clientId":"1",
    "clientVersion":"3.3.827.31",
    "language":"en",
    "pcId":hashlib.md5(auth.pcid.encode("utf-8")).hexdigest(),
    "product":RO_PRODUCT,
    "region":"",
}

})
r.add_nonce()
logging.debug(r.run())

token = input("Enter token from `fastboot getvar token`")

r = UnlockRequest(auth, "unlock.update.miui.com", "/api/v3/ahaUnlock", {
  "appId":"1",
  "data":{
    "clientId":"1",
    "clientVersion":"3.3.827.31",
    "language":"en",
    "operate":"unlock",
    "pcId":hashlib.md5(auth.pcid.encode("utf-8")).hexdigest(),
    "product":RO_PRODUCT,
    "region":"",
    "deviceInfo":{
      "boardVersion":"",
      "product":"cepheus",
      "socId":"",
      "deviceName":""
    },
    "deviceToken":token,
}

})
r.add_nonce()
logging.debug(r.run())

