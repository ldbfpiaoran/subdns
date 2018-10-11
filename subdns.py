# -*- coding: utf-8 -*-  
import sys
import asyncio
import aiodns
import os
import uuid
import logging
import colorlog
import argparse
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
    style='%')
handler.setFormatter(formatter)
log = colorlog.getLogger('subdns')
log.addHandler(handler)
log.setLevel(logging.INFO)


class Subdns():
    def __init__(self,
                 subdomain_list,
                 domain,
                 allip_dict,
                 timeout_domain,
                 create_limit,
                 next_scan,
                 domain_result,
                 dns_servers=None):
        self.loop = asyncio.get_event_loop()
        self.subdomain_list = subdomain_list
        self.resolver = aiodns.DNSResolver(timeout=2, loop=self.loop)
        if dns_servers is None:   # '192.168.102.81','192.168.102.82'  
            self.resolver.nameservers = [
                '223.5.5.5', '223.6.6.6', '114.114.114.114'
            ]
        self.domain = domain
        self.allip_dict = allip_dict
        self.ip_con = 5
        self.domain_result = domain_result
        self.scan_total = 0
        self.find_total = 0
        self.semaphore = asyncio.Semaphore(
            8000)  # 协程并发最大   大佬建议是10000  我觉得2000-5000差不多 也不怎么慢
        self.timeout_domain = timeout_domain
        self.next_scan = next_scan
        self.create_limit = create_limit  # 扫描队列分组为了减少内存开销  异步的task内存占用是在是....可调
        self.limit_timeout = 6  # 超时重试次数   默认重试6次

    async def scan(self, sub_domain, sem):
        async with sem:
            self.scan_total += 1
            self.print_msg("remain " + str(self.scan_total) + "  | Found" +
                           str(self.find_total) + '\r')
            try:
                res = await self.resolver.query(sub_domain, "A")
                ret = [ip.host for ip in res]
                if self.is_analysis(ret):
                    log.info(sub_domain + '\t' + str(ret))
                    self.next_scan.append(sub_domain)
                    self.domain_result.append(sub_domain + '\t' + str(ret))
                    self.find_total += 1
            except aiodns.error.DNSError as e:
                err_code, err_msg = e.args[0], e.args[1]
                # 1:  DNS server returned answer with no data
                # 4:  Domain name not found
                # 11: Could not contact DNS servers
                # 12: Timeout while contacting DNS servers
                if err_code not in [1, 4, 11, 12]:
                    log.error('{domain} {exception}'.format(
                        domain=sub_domain, exception=e))
                if err_code in [11, 12]:
                    self.timeout_domain.append(sub_domain)
            except Exception as e:
                log.error(e)
                log.error(sub_domain)

    def is_analysis(self, ret):
        if ret == []:
            return False
        for ip in ret:
            if ip in self.allip_dict.keys():
                if self.allip_dict[ip] < self.ip_con:
                    self.allip_dict[ip] += 1
                else:
                    # log.warning(sub_domain+"   May be a general analysis")
                    return False
            else:
                self.allip_dict[ip] = 1
        return True

    def get_analysis(self):
        log.info('check black list')
        for _ in range(10):
            try:
                res = self.resolver.query(str(uuid.uuid4())+'.'+self.domain, "A")
                res = self.loop.run_until_complete(res)
                for ip in res:
                    self.allip_dict[ip.host] = 5
            except aiodns.error.DNSError as e:
                err_code, err_msg = e.args[0], e.args[1]
                # 1:  DNS server returned answer with no data
                # 4:  Domain name not found
                # 11: Could not contact DNS servers
                # 12: Timeout while contacting DNS servers
                if err_code not in [1, 4, 11, 12]:
                    log.error('{domain} {exception}'.format(
                        domain=self.domain, exception=e))
            except Exception as e:
                log.error(e)
        
                    

    @staticmethod
    def print_msg(msg=None, left_align=True):
        if left_align:
            sys.stdout.write('\r' + msg)
        sys.stdout.flush()

    def run(self):
        log.info("start scan  " + self.domain)
        for namelist in self.subdomain_list:
            tasks = [
                asyncio.ensure_future(
                    self.scan(
                        sub_domain=sub.replace("." + self.domain, '') + "." +
                        self.domain,
                        sem=self.semaphore)) for sub in namelist
            ]  # 内存占用太大
            self.loop.run_until_complete(asyncio.wait(tasks))

        while self.timeout_domain != [] and len(
                self.timeout_domain) > 10 and self.limit_timeout > 0:
            self.limit_timeout -= 1
            log.error(len(self.timeout_domain))
            err_domain = self.list_of_groups(self.timeout_domain,
                                             self.create_limit)
            self.timeout_domain = []
            for namelist in err_domain:
                tasks = [
                    asyncio.ensure_future(
                        self.scan(
                            sub_domain=sub.replace("." + self.domain, '') + "."
                            + self.domain,
                            sem=self.semaphore)) for sub in namelist
                ]  # 内存占用太大
                self.loop.run_until_complete(asyncio.wait(tasks))
        # self.loop.close()         #  最后关闭
        log.warning("Total  scan " + str(self.scan_total) + " times")

    def list_of_groups(self, init_list, children_list_len):
        list_of_groups = zip(*(iter(init_list), ) * children_list_len)
        end_list = [list(i) for i in list_of_groups]
        count = len(init_list) % children_list_len
        end_list.append(init_list[-count:]) if count != 0 else end_list
        return end_list



def start(domain, subdomain_list, allip_dict, create_limit, timeout_domain,
          domain_result, next_scan):
    s = Subdns(
        domain=domain,
        subdomain_list=subdomain_list,
        allip_dict=allip_dict,
        create_limit=create_limit,
        timeout_domain=timeout_domain,
        domain_result=domain_result,
        next_scan=next_scan)
    s.run()


    


def main():
    parser = argparse.ArgumentParser(description='to use get subnames of dns')
    parser.add_argument("-v", "--version", action='version', version=' 1.0')
    parser.add_argument(
        "-d",
        "--dict",
        type=str,
        help='Specify a dictionary',
        default='test.txt')
    parser.add_argument(
        "-u", "--domain", type=str, help='Designated domain name')
    parser.add_argument("-s", "--deep", type=int, help='Domain depth')
    parser.add_argument(
        "-n",
        "--next",
        type=str,
        help='Specify a dictionary',
        default='mini_names.txt')
    args = parser.parse_args()

    if args.domain is None:
        log.error("Please input domain  such as python subdns.py -u baidu.com")
        sys.exit()
    domain = args.domain  # scan  domain
    subname_dict = args.dict  # dict  name
    next_n = args.next
    if os.name == 'nt':  # subname_dict   字典物理地址
        subname_dict = os.getcwd() + '\\dict\\' + subname_dict
        save_name = os.getcwd() + '\\output\\' + domain + '.txt'
        next_subname = os.getcwd() + '\\dict\\' + next_n
    else:
        subname_dict = os.getcwd() + '/dict/' + subname_dict
        save_name = os.getcwd() + '/output/' + domain + '.txt'
        next_subname = os.getcwd() + '/dict/' + next_n
    log.info("check  dict is " + subname_dict)

    subname_list = []  # scan domain list
    allip_dict = {} # black list
    domain_result = []  # subname list
    next_scan = []  # deep scan list
    timeout_domain = []  # timeout retry list
    next_subname_list = []  # deep scan list

    create_limit = 300000  # 300000#  扫描队列分组为了减少内存开销  异步的task内存占用是在是....可调
    count = 0
    count_list = []
    domain_count = 0
    with open(subname_dict) as f:
        for i in f.readlines():
            domain_count += 1
            count += 1
            count_list.append(i.replace('\n', ''))
            if count == create_limit:
                subname_list.append(count_list)
                count_list = []
                count = 0
        if count_list != []:
            subname_list.append(count_list)
            count_list = []

    log.info("A total of {} domain names need to be scanned".format(
        str(domain_count)))

    s = Subdns(
        domain=domain,
        subdomain_list=subname_list,
        allip_dict=allip_dict,
        create_limit=create_limit,
        timeout_domain=timeout_domain,
        domain_result=domain_result,
        next_scan=next_scan)
    s.get_analysis()
    #log.error(allip_dict)
    s.run()

    log.warning("Total  scan " + str(len(domain_result)) + " subname")

    with open(save_name, 'w') as sa:
        for z in domain_result:
            sa.write(z + '\n')

    log.warning("The result is save in " + save_name)
    
    '''
    
    deep scan sudname


    '''
    if args.deep:
            '''
    Load deep scan dictionary
    
    '''

    with open(next_subname) as x:
        for i in x.readlines():
            domain_count += 1
            count += 1
            count_list.append(i.replace('\n', ''))
            if count == create_limit:
                next_subname_list.append(count_list)
                count_list = []
                count = 0
        if count_list != []:
            next_subname_list.append(count_list)
            count_list = []

        next_scan = list(set(next_scan))
        while next_scan != []:
            name = next_scan[0]
            timeout_domain = []
            domain_result = []
            next_scan.remove(name)
            s = Subdns(
                domain=name,
                subdomain_list=next_subname_list,
                allip_dict=allip_dict,
                create_limit=create_limit,
                timeout_domain=timeout_domain,
                domain_result=domain_result,
                next_scan=next_scan)
            s.get_analysis()
            s.run()

            with open(save_name, 'a+') as sa:
                for z in domain_result:
                    sa.write(z + '\n')

            log.warning("The result is save in" + save_name)


if __name__ == "__main__":
    main()
