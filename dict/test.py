maa = []

with open('mini_names.txt','r') as f:
    for i in f.readlines():
        maa.append(i)

with open('subnames_full.txt','r') as z:
    for i in z.readlines():
        maa.append(i)

maa = list(set(maa))

with open('mini_names1.txt','w') as e:
    for i in maa:
        e.write(i)