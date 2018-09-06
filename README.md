
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Django.svg)
# subdns


[![asciicast](https://asciinema.org/a/199913.png)](https://asciinema.org/a/199913)

采用 asyncio+aiodns协程进行子域名爆破
因为协程生成协程池会消耗大量系统资源，所以会对字典进行切割
如果发生内存占用过高建议修改create_limit的值
unix系统需要修改 open files 的值  协程默认并发量4000如果带宽足够可以增加到10000

实际测试  在带宽足够的情况下可达到每分钟50万+次查询

对于泛解析 采用黑明单的方法  先去请求几个不存在的域名  然后判断加入泛解析黑名单

对于一些请求超时  在所有字典跑完后  回去做重试操作
默认如果重试超过60次结果不变停止重试

在字典越大效果越好。。。
字典小反而影响速度   我自己是整理了一个1000万的字典。。。 
效果不错  不过在5m的带宽跑二级域名需要十几个小时


 用法
-------

python subdns.py -u example.com -d test.txt 
