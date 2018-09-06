

name_list = []

mei_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','1','2','3','4','5','6','7','8','9','0']

for n1 in mei_list:
    name_list.append(n1)
    for n2 in mei_list:
        name_list.append(n1+n2)
        for n3 in mei_list:
            name_list.append(n1+n2+n3)
            for n4 in mei_list:
                name_list.append(n1+n2+n3+n4)


with open("4num.txt",'w') as f:
    for i in name_list:
        f.write(i+'\n')
