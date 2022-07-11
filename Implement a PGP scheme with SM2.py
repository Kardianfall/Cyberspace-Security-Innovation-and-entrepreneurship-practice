import Use SM2 to implement PGP scheme, SM2, SM2 key generation, MD5, prepare files

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
