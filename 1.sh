#!/bin/bash

response=$(curl -k -i -X POST -H "Content-Length: 41" -H "Sec-Ch-Ua: \"Chromium\";v=\"109\", \"Not_A Brand\";v=\"99\"" -H "Accept: application/json, text/plain, */*" -H "Content-Type: application/json; charset=UTF-8" -H "Sec-Ch-Ua-Mobile: ?0" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36" -H "Token: 213b7a8753c8e0f450de82b50ed35abd" -H "Sec-Ch-Ua-Platform: \"Windows\"" -H "Origin: https://127.0.0.1:5003" -H "Sec-Fetch-Site: same-origin" -H "Sec-Fetch-Mode: cors" -H "Sec-Fetch-Dest: empty" -H "Accept-Encoding: gzip, deflate" -H "Accept-Language: zh-CN,zh;q=0.9" -d '{"username":"admin","password":"arlpass"}' https://127.0.0.1:5003/api/user/login)

token=$(echo "$response" | grep Token | awk '{print $2}')

echo "Token value is: $token"
