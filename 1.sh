#!/bin/bash

# 设置请求URL和请求体
url="https://127.0.0.1:5003/api/user/login"
data='{"username":"admin","password":"arlpass"}'

# 设置请求头部信息
headers=(
    "Content-Type: application/json; charset=UTF-8"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36"
    "Origin: https://10.147.19.32:5003"
)

# 发送请求并提取响应包Token
token=$(curl -s -X POST -H "${headers[@]}" -d "${data}" "${url}" | jq -r '.token')

# 输出响应包Token
echo "Token: ${token}"
