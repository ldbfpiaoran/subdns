# -*- coding: utf-8 -*-
import sys
import asyncio
import aiodns
import logging
import colorlog
import argparse
import IPy
import random
import ipaddress
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



class Subscan:
    def __init__(self, paras={}):
        self.is_fuzz = paras['fuzz'] if paras.get('fuzz') else False
        self.fuzz_data = paras['fd'] if paras.get('fd') else ""
        self.deep = paras['deep'] if paras.get('deep') else 5
        self.test = paras['test'] if paras.get('test') else False
        self.check_analysis = True if paras.get('analysis_domain') else False  # 通过cname 判断泛解析 这个方法极度损耗性能相当于查询两遍dns
        self.analysis_domain = paras['analysis_domain'] if paras.get('analysis_domain') else []
        self.queue = asyncio.Queue()
        self.check_bk = paras['check_bk']
        self.black_list = {}  # 黑名单ip  黑明单键值为10
        self.bk_domain = paras['bk_domain'] if paras.get('bk_domain') else []  # openvpn  world.taobao.com 这样的
        self.bk_limit = 10  # 黑名单次数
        self.bk_ipdata = ['127.0.0.0/8', '0.0.0.0/8']
        self.domain_list = {}
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, rotate=True)
        self.sem = asyncio.BoundedSemaphore(5000)
        self.resolver.nameservers = ['223.5.5.5', '223.6.6.6', '114.114.114.114']
        self.domain = paras.get('domain')
        self.dictname = "mini_names.txt" #"big_subnames.txt"  # 一级域名大字典
        if paras.get('dictname'):
            self.dictname = paras['dictname']
        self.sec_dictname = "test.txt" #"subdict.txt"  # 递归小字典
        self.semaphore = asyncio.Semaphore(5000)  # 协程并发量  2m带宽
        log.info(f'开始扫描子域名 {self.domain}')
        self.subdomain_list = set()
        self.scan_total = 0
        self.find_total = 0


    @staticmethod
    def print_msg(msg=None, left_align=True):
        if left_align:
            sys.stdout.write('\r' + msg)
        sys.stdout.flush()

    def init_bk(self):
        '''
            初始化 黑名单 随机不存在域名 判断泛解析
            :return:
            '''
        tasks = [asyncio.ensure_future(self.check_black()) for _ in range(2000)]
        self.loop.run_until_complete(asyncio.wait(tasks))

    async def check_black(self):
        subd = ''.join(random.sample('abcdefghijklmnopqrstuvwxyz', random.randint(6, 12)))
        res = await self.query(subd, self.semaphore, "A")
        if res:
            for ip in res:
                self.black_list[ip.host] = self.bk_limit

    async def query(self, sub_domain, sem, q_type, num=1):
        async with sem:
            try:
                sub_domain = sub_domain + "." + self.domain
                return await self.resolver.query(sub_domain, q_type)
            except aiodns.error.DNSError as e:
                err_code, err_msg = e.args[0], e.args[1]
                # 1:  DNS server returned answer with no data
                # 4:  Domain name not found
                # 11: Could not contact DNS servers
                # 12: Timeout while contacting DNS servers
                if err_code not in [1, 4, 11, 12]:
                    return
                if err_code in [11, 12]:
                    # 超时重试 处理
                    if num <= 2:
                        num += 1
                        await self.query(sub_domain, sem, q_type)
                    return
            except Exception as e:
                print(e)
                return


    def is_black(self, ips):
        '''
        黑名单相关操作
        :param subdomain:
        :return: true false
        '''
        for ip in ips:
            ip_num = self.black_list.get(ip)
            if ip_num:
                if ip_num == self.bk_limit:
                    return False
                else:
                   self.black_list[ip] += 1
            else:
                 self.black_list[ip] = 1
            for bkip in self.bk_ipdata:
                if ip in IPy.IP(bkip):
                    return False
        return True

    async def brute_domain(self):
        while True:
            sub = await self.queue.get()
            self.scan_total += 1
            self.print_msg("remain " + str(self.scan_total) + "  | Found" +
                           str(self.find_total) + '\r')
            if self.check_analysis:
                cname = await self.query(sub, self.semaphore, "CNAME")
                if cname:
                    cname = cname.cname
                    if cname in self.analysis_domain:
                        continue
            res = await self.query(sub, self.semaphore, "A")
            if res:
                subdomain = sub+"."+self.domain
                sub_ips = [r.host for r in res]
                if self.is_black(sub_ips):
                    self.find_total += 1
                    log.info(f'{subdomain} {sub_ips}')
                    self.save_and_next(subdomain, sub_ips)
            self.queue.task_done()


    def get_deep(self, subname):
        tex = subname.replace("."+self.domain, "")
        return len(tex.split("."))+1

    def save_and_next(self, subname, ips, num=1):
        if not self.test:
            try:
                if subname not in self.subdomain_list:
                    self.subdomain_list.add(subname)
                    with open('output/'+self.domain+".txt", "a") as f:
                        f.write(subname+"\t"+str(ips)+"\n")
                sub_deep = self.get_deep(subname)
                sub_text = subname.replace("."+self.domain, "")
                if sub_deep <= self.deep and not self.is_fuzz:   # 域名深度
                    with open('dict/' + self.sec_dictname, 'r') as f:
                        for line in f:
                            self.queue.put_nowait(line.strip().lower()+"."+sub_text)
            except Exception as e:
                log.error(str(e))
                self.session.rollback()

        """
        拆出来 一条一条插入 防止任务异常
        :return:
        """

    async def start_brute(self):
        with open('dict/'+self.dictname, 'r') as f:
            for line in f:
                domain = line.strip().lower()
                if self.is_fuzz:   #  加个fuzz逻辑 such  mozi-console.alibaba.com   mozi-FUZZ.alibaba.com
                    domain = self.fuzz_data.replace("FUZZ",domain)
                if not self.check_bk_domain(domain):
                    self.queue.put_nowait(domain)
        brute_tasks = [self.loop.create_task(self.brute_domain()) for _ in range(2000)]
        await self.queue.join()
        for task in brute_tasks:
            task.cancel()

    def check_bk_domain(self, domain):
        if not self.bk_domain:
            return False
        for bk_domain in self.bk_domain:
            if bk_domain in domain:
                return True
        return False

    def main(self):
        if self.check_bk:  # check
            self.init_bk()
        try:
            log.info("start brute")
            self.loop.run_until_complete(self.start_brute())
        finally:
            self.loop.close()


def main():
    parser = argparse.ArgumentParser(description='to use get subnames of dns')
    parser.add_argument("-v", "--version", action='version', version=' 2.0')
    parser.add_argument(
        "-d",
        "--dict",
        type=str,
        help='Specify a dictionary',
        default='test.txt')
    parser.add_argument(
        "-u", "--domain", type=str, help='Designated domain name')
    parser.add_argument("-s", "--deep", type=int, help='Domain depth', default=5)
    parser.add_argument("-c", "--check_bk", type=str, help='check  random subdomain', default=True)
    parser.add_argument("-an", "--analysis_domain", type=str, help='analysis cname')
    parser.add_argument("-fd", "--fuzz_data", type=str, help='FUZZ data')
    parser.add_argument(
        "-n",
        "--next",
        type=str,
        help='Specify a dictionary',
        default='mini_names.txt')

    args = parser.parse_args()
    params = {}
    if args.fuzz_data:
        params['fuzz'] = True
        params['fd'] = args.fuzz_data
    if args.domain is None:
        log.error("Please input domain  such as python subdns.py -u baidu.com")
        sys.exit()
    params['domain'] = args.domain
    if args.check_bk.lower() == 'false':
        params['check_bk'] = False
    else:
        params['check_bk'] = True
    params['deep'] = args.deep
    params['sec_dictname'] = args.next
    params['dictname'] = args.dict
    if args.analysis_domain:
        params['analysis_domain'] = args.analysis_domain.split(',')
    sc = Subscan(paras=params)
    sc.main()

if __name__ == "__main__":
    main()
