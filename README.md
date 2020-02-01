# walking_robot
A tool to verify remote code execution：一个验证远程代码执行的工具</br>
</br>
编程语言：Python 3.6.5</br>
调用库：python-namp 0.6.1</br>
# 文件目录
walking_robot.py：主程序</br>
/imports/req.py：验证请求</br>
/imports/poc_lists.py：验证代码</br>
# 如何使用
>>> python walking_robot.py ip</br></br>
>>> python walking_robot.py -u ip -p port</br>
>>> python walking_robot.py -f urls.txt</br>
>>> python walking_robot.py -r urls.txt -p port</br>
>>> python walking_robot.py -h --help</br>
