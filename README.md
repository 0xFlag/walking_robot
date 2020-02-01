# walking_robot
A tool to verify remote code execution：一个验证远程代码执行的工具</br>
</br>
编程语言：Python 3.6.5</br>
调用库：python-namp 0.6.1</br>
# 说明
这个程序主要是批量来验证有没有远程代码执行漏洞的，可以自己自定义添加验证代码，主要修改需要看代码结构。
# 文件目录
walking_robot.py：主程序</br>
/imports/req.py：验证请求</br>
/imports/poc_lists.py：验证代码</br>
# 如何使用
> python walking_robot.py ip</br>
> python walking_robot.py -u ip -p port</br>
> python walking_robot.py -f urls.txt</br>
> python walking_robot.py -r urls.txt -p port</br>
> python walking_robot.py -h --help</br>
</br>
Linux 可以直接执行，测试是在kali 下测试的，需要nmap</br>
Windows 需要安装windows 版的nmap，测试是7.80</br>
Windows 安装windows 版的nmap后还需要修改python-nmap库文件，具体修改：</br>
*:\Python36\Lib\site-packages\nmap\nmap.py
</br></br>
def __init__(self, nmap_search_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap', r"nmap.exe 所在路径")):
</br>
# 参考
</br>灵感来自freebuf：</br>
https://www.freebuf.com/articles/system/223181.html</br>
部分远程代码验证：</br>
https://github.com/pan-unit42/iocs/blob/master/mirai/ECHOBOT_28thOct2019.md</br>
https://github.com/pan-unit42/iocs/blob/master/mirai/ECHOBOT_6thAug2019.md</br>
https://unit42.paloaltonetworks.com/new-mirai-variant-adds-8-new-exploits-targets-additional-iot-devices/
