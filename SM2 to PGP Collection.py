from tkinter import FALSE
from gmssl import sm2
from base64 import b64encode, b64decode
import hashlib
from datetime import datetime
today = datetime.today().strftime('%Y%m%d')

############################md5
def md5(a):
	data=a
	return hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()

############################公私钥生成

from random import SystemRandom

class CurveFp:
	def __init__(self, A, B, P, N, Gx, Gy, name):
		self.A = A
		self.B = B
		self.P = P
		self.N = N
		self.Gx = Gx
		self.Gy = Gy
		self.name = name

sm2p256v1 = CurveFp(
	name="sm2p256v1",
	A=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
	B=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
	P=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
	N=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
	Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
	Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
)

def multiply(a, n, N, A, P):
	return fromJacobian(jacobianMultiply(toJacobian(a), n, N, A, P), P)

def add(a, b, A, P):
	return fromJacobian(jacobianAdd(toJacobian(a), toJacobian(b), A, P), P)

def inv(a, n):
	if a == 0:
		return 0
	lm, hm = 1, 0
	low, high = a % n, n
	while low > 1:
		r = high//low
		nm, new = hm-lm*r, high-low*r
		lm, low, hm, high = nm, new, lm, low
	return lm % n

def toJacobian(Xp_Yp):
	Xp, Yp = Xp_Yp
	return (Xp, Yp, 1)

def fromJacobian(Xp_Yp_Zp, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	z = inv(Zp, P)
	return ((Xp * z**2) % P, (Yp * z**3) % P)

def jacobianDouble(Xp_Yp_Zp, A, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	if not Yp:
		return (0, 0, 0)
	ysq = (Yp ** 2) % P
	S = (4 * Xp * ysq) % P
	M = (3 * Xp ** 2 + A * Zp ** 4) % P
	nx = (M**2 - 2 * S) % P
	ny = (M * (S - nx) - 8 * ysq ** 2) % P
	nz = (2 * Yp * Zp) % P
	return (nx, ny, nz)

def jacobianAdd(Xp_Yp_Zp, Xq_Yq_Zq, A, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	Xq, Yq, Zq = Xq_Yq_Zq
	if not Yp:
		return (Xq, Yq, Zq)
	if not Yq:
		return (Xp, Yp, Zp)
	U1 = (Xp * Zq ** 2) % P
	U2 = (Xq * Zp ** 2) % P
	S1 = (Yp * Zq ** 3) % P
	S2 = (Yq * Zp ** 3) % P
	if U1 == U2:
		if S1 != S2:
			return (0, 0, 1)
		return jacobianDouble((Xp, Yp, Zp), A, P)
	H = U2 - U1
	R = S2 - S1
	H2 = (H * H) % P
	H3 = (H * H2) % P
	U1H2 = (U1 * H2) % P
	nx = (R ** 2 - H3 - 2 * U1H2) % P
	ny = (R * (U1H2 - nx) - S1 * H3) % P
	nz = (H * Zp * Zq) % P
	return (nx, ny, nz)

def jacobianMultiply(Xp_Yp_Zp, n, N, A, P):
	Xp, Yp, Zp = Xp_Yp_Zp
	if Yp == 0 or n == 0:
		return (0, 0, 1)
	if n == 1:
		return (Xp, Yp, Zp)
	if n < 0 or n >= N:
		return jacobianMultiply((Xp, Yp, Zp), n % N, N, A, P)
	if (n % 2) == 0:
		return jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P)
	if (n % 2) == 1:
		return jacobianAdd(jacobianDouble(jacobianMultiply((Xp, Yp, Zp), n // 2, N, A, P), A, P), (Xp, Yp, Zp), A, P)

class PrivateKey:
	def __init__(self, curve=sm2p256v1, secret=None):
		self.curve = curve
		self.secret = secret or SystemRandom().randrange(1, curve.N)

	def publicKey(self):
		curve = self.curve
		xPublicKey, yPublicKey = multiply((curve.Gx, curve.Gy), self.secret, A=curve.A, P=curve.P, N=curve.N)
		return PublicKey(xPublicKey, yPublicKey, curve)

	def toString(self):
		return "{}".format(str(hex(self.secret))[2:].zfill(64))

class PublicKey:
	def __init__(self, x, y, curve):
		self.x = x
		self.y = y
		self.curve = curve

	def toString(self, compressed=True):
		return {
			True:  str(hex(self.x))[2:],
			False: "{}{}".format(str(hex(self.x))[2:].zfill(64), str(hex(self.y))[2:].zfill(64))
		}.get(compressed)

def scmy():
	priKey = PrivateKey()
	pubKey = priKey.publicKey()
	return priKey.toString(),pubKey.toString(compressed = False)



#a,b=scmy()



############################sm2具体
#66
#128
#SM2_PRIVATE_KEY = "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5"
#SM2_PUBLIC_KEY = "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207"
def ini(SM2_PRIVATE_KEY,SM2_PUBLIC_KEY):
    return sm2.CryptSM2(public_key=SM2_PUBLIC_KEY, private_key=SM2_PRIVATE_KEY)

class sm2Encrypt:
    # 加密

    def encrypt(self, info,key):
        encode_info = key.encrypt(info.encode(encoding="utf-8"))
        encode_info = b64encode(encode_info).decode()  # 将二进制bytes通过base64编码
        return encode_info

    # 解密
    def decrypt(self, info,key):
        decode_info = b64decode(info.encode())  # 通过base64解码成二进制bytes
        decode_info = key.decrypt(decode_info).decode(encoding="utf-8")
        return decode_info


#sm2_crypt=ini(a,b)

#使用指南
#md5(string)
#a,b=scmy()   a 私钥 b 公钥
#sm2_crypt=ini(a,b)  初始化
#sm2 = sm2Encrypt()  初始化sm2类
# 加密的密码
#encrypy_pwd = sm2.encrypt(string)

# 解密的密码
#decrypt_pwd = sm2.decrypt(encrypy_pwd)




#########PGP

namea=input("name_1:")
nameb=input("name_2:")

a1,a2=scmy()
b1,b2=scmy()

k1=ini(a1,a2)
k2=ini(b1,b2)

a={"name":namea,"privatekey":a1,"publickey":a2}	
b={"name":nameb,"publickey":b1,"privatekey":b2}	

print("User information generated and generate public-private key pairs")
print(a)
print(b)

print("Now user [",namea,"] sends mail to user[",nameb,"]")
email=input("Please enter the email content:")
mddd=md5(email)
email=str(len(email))+email
print("Encrypt the content with MD5, add the user name and timestamp:")
email_after_md5=mddd+namea+today
print(email_after_md5)
print("")
print("Now user [",namea,"] use sm2 encrypt with private key first:")
#sm2_crypt=ini(a1,a2)  
sm2 = sm2Encrypt()
email_after_as = sm2.encrypt(email_after_md5,k1)
print(email_after_as)
print("")
print("Then add length and original text and use sm2 encrypt with the public key of [",nameb,"] and send it to [",nameb,"] :")
#sm2_cryptt=ini(b1,b2)
email_before_bg=email+email_after_as
sm22=sm2Encrypt()
email_after_bg=sm22.encrypt(email_before_bg,k2)
print(email_after_bg)
print("")
print("[",nameb,"] use sm2 decrypt with its own public key after receiving it:")
email_after_bgj=sm22.decrypt(email_after_bg,k2)
print(email_after_bgj)
print("")
print("The beginning of the message is the length of the mailbox, so you can tell the content of the message is(Please enter the length of all content before encrypting the summary):")
bemail=input()
lenth=int(bemail)
afteras=email_after_bgj[lenth:]
ll=len(str(bemail))
contan=email_after_bgj[ll:lenth]
print("The content of the email is:",contan)
print("Message summary:",afteras)
print("")
print("Now decrypt with [",namea,"]'s public key:")
jiea=sm2.decrypt(afteras,k1)
print(jiea)
print("[",nameb,"] generate a summary of the mail content with MD5:")
md55=md5(contan)
print(md55)
print("If the value of summary + user name + timestamp you see is equal, it means that the email is truste")
print("Project：Using SM2 to realize PGP scheme completion")
