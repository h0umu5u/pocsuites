# pocsuites

一个开源的、功能强大的漏洞验证与 PoC/Exp 开发框架，支持快速验证目标是否存在安全漏洞，同时为安全研究人员提供便捷的 PoC 编写与扩展能力
编写 PoC（Proof of Concept）脚本，对目标系统进行漏洞探测与验证，并具有良好的模块化设计

遵循统一的类结构，通常需要继承 POCBase或相关基类，并实现指定的方法，例如：_verify、_attack等。

from pocsuite3.api import Output, POCBase, register_poc, requests, logger

class DemoPOC(POCBase):
    vulID = '0'
    version = '1.0'
    author = ['yourname']
    vulDate = ''
    createDate = ''
    updateDate = ''
    references = ['https://example.com']
    name = '示例漏洞检测 PoC'
    appPowerLink = ''
    appName = '示例应用'
    appVersion = 'All'
    vulType = 'Example-Vuln'
    desc = '''
    这里填写漏洞描述
    '''
    samples = ['http://example.com/vuln']
    install_requires = ['']

    def _verify(self):
        result = {}
        target = self.url
        # 构造请求，验证漏洞
        try:
            resp = requests.get(target + "/test_vuln_path", timeout=10)
            if "vulnerable_string" in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['VerifyInfo']['Payload'] = "/test_vuln_path"
        except Exception as e:
            logger.error(e)
        return self.parse_output(result)

    def _attack(self):
        # 如果有利用逻辑，可以在这里实现
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('目标不存在漏洞')
        return output

register_poc(DemoPOC)
