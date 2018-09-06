
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Django.svg)
# subdns


采用 asyncio+aiodns协程进行子域名爆破
因为协程生成协程池会消耗大量系统资源，所以会对字典进行切割
如果发生内存占用过高建议修改create_limit的值
unix系统需要修改 open files 的值  协程默认并发量4000如果带宽足够可以增加到10000


 用法
-------

python subdns.py -u example.com -d test.txt 
