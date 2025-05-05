import requests
import json
import time
import hashlib
import logging
from urllib.parse import unquote

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('日志.txt', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def md5_encrypt(text):
    return hashlib.md5(text.encode()).hexdigest()

def main():
    try:
        # 基础信息
        password = "batman18"
        account = "lutuo6398nfx@126.com"
        timestamp = int(time.time() * 1000)
        logging.info(f"当前时间戳: {timestamp}")

        # 生成签名
        encrypt_content = f"account={account}&code=&device=&password={password}&timestamp={timestamp}&key=ACblockandwallets"
        sign = md5_encrypt(encrypt_content)
        logging.info(f"生成的签名: {sign}")
        sign = sign.upper()
        logging.info(f"大写的签名: {sign}")

        # 登录获取token
        login_url = "https://urgwgoskun.sfuzcgddzr.com/api/auth/pwd_login"
        login_data = {
            "account": account,
            "password": password,
            "code": "",
            "device": "",
            "timestamp": timestamp,
            "sign": sign
        }
        login_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 9; M973Q Build/PQ3B.190801.07101020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)",
            "Content-Type": "application/json",
            "Content-Length": "143",
            "Host": "urgwgoskun.sfuzcgddzr.com",
            "Connection": "Keep-Alive"
        }

        login_response = requests.post(login_url, json=login_data, headers=login_headers)
        login_result = login_response.json()
        logging.info(f"登录响应: {login_result}")
        login_token = login_result.get("data", {}).get("accessToken")
        logging.info(f"登录token: {login_token}")

        # 获取信息
        airdrop_url = "https://urgwgoskun.sfuzcgddzr.com/api/index/getAirdrop?lang=zh_CN"
        airdrop_headers = {
            "Authorization": login_token,
            "user-agent": "Mozilla/5.0 (Linux; Android 9; M973Q Build/PQ3B.190801.07101020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)",
            "Host": "urgwgoskun.sfuzcgddzr.com",
            "Connection": "Keep-Alive"
        }

        airdrop_response = requests.get(airdrop_url, headers=airdrop_headers)
        logging.info(f"信息请求状态码: {airdrop_response.status_code}")
        logging.info(f"信息请求头: {airdrop_headers}")
        airdrop_result = airdrop_response.json()
        logging.info(f"获取信息响应: {airdrop_result}")
        
        if not airdrop_result.get("data"):
            logging.error("信息响应中没有data字段")
            raise Exception("获取信息失败：响应中没有data字段")
            
        auth_token = airdrop_result.get("data", {}).get("token")
        urls = airdrop_result.get("data", {}).get("urls", [])
        
        if not auth_token:
            logging.error("token获取失败")
            raise Exception("获取token失败")
            
        if not urls:
            logging.error("URL获取失败")
            raise Exception("获取URL失败")
            
        # 从第一个URL中提取ID
        first_url = urls[0]
        auth_id = first_url.split("id=")[1].split("&")[0] if "id=" in first_url else None
        
        if not auth_id:
            logging.error("从URL中提取ID失败")
            raise Exception("从URL中提取ID失败")
            
        logging.info(f"token: {auth_token}")
        logging.info(f"ID: {auth_id}")

        # 上传信息
        kyc_url = "https://api.ttx.vip/api/v1/act/kyc/auth"
        kyc_data = {
            "activityId": auth_id,
            "imageUrl": "filesUpload/ex1/setting/6b2d01968bbb48e39f738994fa28d259_1746364044102.jpg",
            "language": "zh-CN"
        }
        kyc_headers = {
            "host": "api.ttx.vip",
            "content-length": "133",
            "authorization": f"Bearer {auth_token}",
            "exch-client-type": "PC",
            "exch-token": auth_token,
            "exch-id": "1",
            "exch-language": "zh_CN",
            "exch-device-id": "1562f459d47052e379a98791f7ef4b927cb77529e3298b6873d691225c6bdce6",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/135.0.0.0",
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://www.ttx.vip",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.ttx.vip/",
            "accept-language": "zh-CN,zh;q=0.9",
            "priority": "u=1, i"
        }

        kyc_response = requests.post(kyc_url, json=kyc_data, headers=kyc_headers)
        kyc_result = kyc_response.json()
        logging.info(f"KYC响应: {kyc_result}")
        
        biz_id = kyc_result.get("data", {}).get("biz_id")
        face_token = kyc_result.get("data", {}).get("token")
        logging.info(f"业务ID: {biz_id}")
        logging.info(f"识别token: {face_token}")

        # 获取用户信息
        user_info_url = f"https://api-idn.megvii.com/faceid/lite/get_user_info?token={face_token}"
        user_info_headers = {
            "host": "api-idn.megvii.com",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/136.0.0.0",
            "accept": "*/*",
            "x-requested-with": "XMLHttpRequest",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": f"https://api-idn.megvii.com/faceid/lite/do?token={face_token}",
            "accept-language": "zh-CN,zh;q=0.9",
            "priority": "u=1, i"
        }

        user_info_response = requests.get(user_info_url, headers=user_info_headers)
        user_info_result = user_info_response.json()
        logging.info(f"用户信息响应: {user_info_result}")
        
        # 获取完整的biz_id
        verify_biz = user_info_result.get("biz_id")
        if not verify_biz:
            logging.error("获取biz_id失败")
            raise Exception("获取biz_id失败")
        logging.info(f"验证业务ID: {verify_biz}")

        # 上传视频
        face_url = "https://api-idn.megvii.com/faceid/lite/still"
        face_headers = {
            'User-Agent': "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/135.0.0.0",
            'Accept-Encoding': "gzip, deflate, br, zstd",
            'x-requested-with': "XMLHttpRequest",
            'origin': "https://api-idn.megvii.com",
            'sec-fetch-site': "same-origin",
            'sec-fetch-mode': "cors",
            'sec-fetch-dest': "empty",
            'referer': f"https://api-idn.megvii.com/faceid/lite/videostill?token={face_token}",
            'accept-language': "zh-CN,zh;q=0.9",
            'priority': "u=1, i"
        }

        # 读取视频文件
        file_path = r"C:\Users\Administrator\AppData\Roaming\Reqable\tmp\d4b726c0-d35d-4bff-bf88-982ffd8a1bec"
        try:
            with open(file_path, 'rb') as f:
                files = [
                    ('video', ('d4b726c0-d35d-4bff-bf88-982ffd8a1bec', f, 'application/octet-stream'))
                ]
                payload = {'token': face_token}
                face_response = requests.post(face_url, data=payload, files=files, headers=face_headers)
                face_result = face_response.json()
                logging.info(f"人脸识别响应: {face_result}")
        except Exception as e:
            logging.error(f"上传人脸照片失败: {str(e)}")
            raise Exception("上传人脸照片失败")

        # 等待一段时间让服务器处理
        time.sleep(2)

        # 获取返回URL
        return_url = f"https://api-idn.megvii.com/faceid/lite/get_return_url?token={face_token}&biz_id={verify_biz}"
        return_headers = {
            "host": "api-idn.megvii.com",
            "perm": "faceid_lite",
            "x-requested-with": "XMLHttpRequest",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/135.0.0.0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": f"https://api-idn.megvii.com/faceid/lite/videostill?token={face_token}",
            "accept-language": "zh-CN,zh;q=0.9",
            "priority": "u=1, i"
        }

        # 最多尝试3次获取返回URL
        max_retries = 3
        for i in range(max_retries):
            return_response = requests.get(return_url, headers=return_headers)
            return_result = return_response.json()
            logging.info(f"返回URL响应 (尝试 {i+1}/{max_retries}): {return_result}")
            
            if return_result.get("error_message") == "RESULT_NOT_FOUND":
                if i < max_retries - 1:
                    logging.info("等待服务器处理，5秒后重试...")
                    time.sleep(5)
                    continue
                else:
                    logging.error("多次尝试后仍未获取到结果")
                    raise Exception("多次尝试后仍未获取到结果")
            
            data_str = return_result.get("data")
            if data_str:
                try:
                    data = json.loads(data_str)
                    logging.info(f"解析后的返回数据: {data}")
                    break
                except json.JSONDecodeError as e:
                    logging.error(f"解析返回数据失败: {str(e)}")
                    raise Exception("解析返回数据失败")
            else:
                logging.error("返回数据为空")
                raise Exception("返回数据为空")

        # 最终提交
        final_url = "https://www.ttx.vip/zh-CN/airdrop/489240755"
        # 将data对象转换回字符串
        final_data = f"data={json.dumps(data)}"
        final_headers = {
            "host": "www.ttx.vip",
            "content-length": "1199",
            "cache-control": "max-age=0",
            "origin": "https://api-idn.megvii.com",
            "content-type": "application/x-www-form-urlencoded",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/135.0.0.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "referer": "https://api-idn.megvii.com/",
            "accept-language": "zh-CN,zh;q=0.9",
            "priority": "u=0, i"
        }

        final_response = requests.post(final_url, data=final_data, headers=final_headers)
        final_result = unquote(final_response.text)
        logging.info(f"最终响应: {final_result}")

    except Exception as e:
        logging.error(f"发生错误: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main() 
