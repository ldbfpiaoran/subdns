import logging
import colorlog
import argparse
import os
import sys
import dns.resolver
from multiprocessing import Process,Queue
import multiprocessing
import gevent

'''
set log this code is Useless
log.debug  is white ,info is green ,warn is yellow ,error is red ,critical  red!
'''
handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s [%(name)s] [%(levelname)s] %(message)s%(reset)s',
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
)
handler.setFormatter(formatter)
log = colorlog.getLogger('subdns')
log.addHandler(handler)
log.setLevel(logging.INFO)

subname_list = []   #子域名字典   #   统计域名解析ip次数  设置超过十次视为泛解析ip  遇到此ip   pass
dns_server = []   #  办公网不能用其他dns    dns测试  自定义dns后期加上





class Subdns:
    def __init__(self,count_sub,domain,ip_con,name_list,scan_total,domain_result,allip_dict):     #   ,count_sub
        self.domain = domain
        self.ip_con = ip_con
        self.resolver = dns.resolver.Resolver(configure=True)   #  改为False
        self.name_list = name_list
        self.count_sub = count_sub
        self.scan_total = scan_total
        self.resolver.lifetime = self.resolver.timeout = 1.0
        self.domain_result = domain_result
        self.allip_dict = allip_dict




    def search_domain(self,sub):  # sub 子域名前缀
        res = str(sub)+"."+self.domain
        self.count_sub.value = self.count_sub.value -1
        print_msg("remain "+str(self.count_sub.value)+"  | Found"+str(self.scan_total.value)+'\r')
        try:
            result = self.resolver.query(res)
            if result:
                for i in result:
                    i = str(i)
                    if i in self.allip_dict.keys():
                        if self.allip_dict[i] <self.ip_con:    #  改为config配置设置
                            self.allip_dict[i] += 1
                        else:
                            return False
                    else:
                        self.allip_dict[i] = 1
                    res = res+"\t"+i
            self.scan_total.value = self.scan_total.value + 1
            log.info(res)
            self.domain_result.append(res+'\n')
        except Exception as e:
            # log.warning(e)
            return False


    def run(self):
        tasks = []
        for sub in self.name_list:
            tasks.append(gevent.spawn(self.search_domain,sub ))
            gevent.joinall(tasks)


def print_msg(msg=None, left_align=True):
    if left_align:
        sys.stdout.write('\r' + msg )
    sys.stdout.flush()


def run_process(allip_dict,domain_result,count_sub,scan_total,domain,ip_con,name_list):
    s = Subdns(allip_dict=allip_dict,domain_result=domain_result,domain=domain,scan_total=scan_total,ip_con=ip_con,name_list=name_list,count_sub=count_sub)
    s.run()



def main():
    parser = argparse.ArgumentParser(description='to use get subnames of dns')
    parser.add_argument("-v", "--version", action='version', version=' 1.0')
    parser.add_argument("-d", "--dict",type=str,help='Specify a dictionary',default='test.txt')  #   更改为mini_names.txt
    parser.add_argument("-u", "--domain" ,type=str, help='Designated domain name')
    parser.add_argument("-s","--deep",type=int , help='Domain depth',default=2)
    parser.add_argument("-t","--thread", type=int , help='Number of processes',default=4)
    args = parser.parse_args()    #  域名  args.domain    字典  args.dict  深度 args.deep   进程数  args.thread

    if args.domain == None:
        log.error("Please input domain  such as python subdns.py -u baidu.com")
        sys.exit()
    subname = args.domain          #   scan  domain
    subname_dict = args.dict
    if os.name == 'nt':    #subname_dict   字典物理地址
        subname_dict = os.getcwd()+'\\dict\\'+subname_dict
        save_name = os.getcwd()+'\\output\\'+subname+'.txt'
    else:
        subname_dict = os.getcwd()+'/dict/'+subname_dict
        save_name = os.getcwd()+'/output/'+subname+'.txt'
    log.info("check  dict is "+subname_dict)
    with open(subname_dict,'r') as f:
        for  sub in f.readlines():
            sub = sub.replace("\n","")
            subname_list.append(sub)
    count_sub = len(subname_list)
    log.info("total "+str(count_sub)+"  will scan")
    log.info("Start the injection process....")
    flag = count_sub//args.thread - 1

    manager = multiprocessing.Manager()
    domain_result = manager.list()
    allip_dict = manager.dict()
    count_sub = manager.Value("i",count_sub)
    scan_total = manager.Value("i",0)


    s = Subdns(allip_dict=allip_dict,domain_result=domain_result,domain=subname,scan_total=scan_total,ip_con=5,name_list=subname_list,count_sub=count_sub)
    s.run()



    log.warning("Total  scan "+str(len(domain_result))+" subname")

    with open(save_name,'w') as sa:
        for z in domain_result:
            sa.write(z)



if __name__ == '__main__':
    main()

