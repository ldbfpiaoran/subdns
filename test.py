import asyncio
import aiodns

loop = asyncio.get_event_loop()
resolver = aiodns.DNSResolver(loop=loop)
f = resolver.query('6aab376a-281f-47f8-9303-61cca2a09168.baidu.com','A')
result = loop.run_until_complete(f)
print(result)
