import base64
from typing import Dict

# https://pypi.org/project/requests-unixsocket2/
import requests_unixsocket

socket = "minivault.sock"
mvuri = f"http+unix://{socket}"

sess = requests_unixsocket.Session()


def MVUnlock(username, password):
    r = sess.post(
        mvuri + "/unlock", json={"unlock": {"username": username, "password": password}}
    )
    r.raise_for_status()
    result: Dict = r.json()
    if result.get("status") != "success":
        raise Exception(result.get("msg"))


def MVEncrypt(data: bytes) -> str:
    encodedData = base64.urlsafe_b64encode(data).decode()
    r = sess.post(mvuri + "/encrypt", json={"encrypt": {"data": encodedData}})
    r.raise_for_status()
    result: Dict = r.json()
    if result.get("status") != "success":
        raise Exception(result.get("msg"))
    return result.get("msg")


def MVDecrypt(data: str) -> bytes:
    r = sess.post(mvuri + "/decrypt", json={"decrypt": {"data": data}})
    r.raise_for_status()
    result: Dict = r.json()
    if result.get("status") != "success":
        raise Exception(result.get("msg"))
    return base64.urlsafe_b64decode(result.get("msg"))


MVUnlock("admin", "password")
encryptedData = MVEncrypt("minivault test".encode())
print(f"encrypted string: {encryptedData}")
decryptedData = MVDecrypt(encryptedData)
print(f"decrypted string: {decryptedData.decode()}")
