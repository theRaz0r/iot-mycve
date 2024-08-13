# tenda_ac6_stackoverflower_formSetPPTPServer

函数formSetPPTPServer中的startIp 传递到后面sscanf会导致栈溢出。

前端接口为SetPptpServerCfg
![](vx_images/588319791091671.png)


![](vx_images/521198779086793.png)



![](vx_images/366231520866059.png)

显示了errcode 1 
![](vx_images/322493766766748.png)

这里需要pptp_server_enable不等于0，需要等于1才能执行到危险函数sscanf。

![](vx_images/107324515729656.png)

还得先设置pptp_server_start_ip和pptp_server_end_ip的值 