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
#此段出处https://wenku.baidu.com/view/31170d6a28160b4e767f5acfa1c7aa00b52a9d21.html


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
