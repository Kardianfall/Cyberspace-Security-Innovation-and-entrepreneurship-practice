from gmssl import sm3, func

def  sm3_simple(a):
    strs = str(a)
    str_b = bytes(strs, encoding='utf-8')
    result = sm3.sm3_hash(func.bytes_to_list(str_b))
    return result


start=0
a={}
i=start
while True:
    x=str(sm3_simple(i)[:6])
    if a.get(x) ==None:
        a[x]=i;
        i+=1
    else :
        break;

print("find 6 bits collision:%d and %d"%(i,a[x]))
