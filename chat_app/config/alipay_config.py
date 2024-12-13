from alipay import AliPay
import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 支付宝配置
# 注意：每行之间要有换行符，且内容要正确对齐

APP_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuwyEtwfZ53gABBnhti4vU2/9dlY1qX42oP6jiI9DKaq87O7Q1aLCtakmUKjudKIIWXkpVCTyClZCraky2I2utcZz2HG9Is7jjeXyR0ksw/D0Cd0aKgn7RKi7w2HmL6dQYjktDJI4bsQV+RLZu65R0WT89/kxdtWiVKUCoE6M/aysobBecwmnV+8JGOeOqFiq8HRVIW35MwUjoJkqX7+ybItZRTw1GRum7XrLFtmSXSGVlUuxZMkk8eZEfbRdlrEr9iOxDastYKYJKw+j/8kTaLxGYZwgZdIBW+tLNsUZR2AVqGeB5Ra9Oz6LmTxo6DpD0Vj4eVgz/h1SfWLkILrdJAgMBAAECggEAa9n2VuPV9X2g6QESPyCYiiO+5AVQga44oPWwhubtio3uWJLO8wsJxevLPsoVgjammaFVJEeP9VLSNkdi0iDn6eEsqeIAd5CacJ/f1ao/RxrTl/r+KKrCEtmCoJYn5MXIY+Mk5Wng3YwQxM0o/Skbs/YEBoEypb43rZ4IzfFYlODLIxcDUP4/lRapuhwwl/536o+WmJ4G/zk+Eb+MzWDqYsbf8/RlZBX35Kfp5nhWlPME+UT3GgwdrfISOqELM83+dQohfgzf3YcbfpTNECP/0OuZxtm4Q6DWhR1Eez1TXbl1AFkt/so5q/lm6IWmDZ/TH852GnzxYxStQ2RczP6d0QKBgQDpp3RxFo+ECmaVTN/e8OvdJ/hGaGIeYwMJwsFFFaORHhvpV6NJ7nz/bfT8/OlGpr9eFRrsN/Z9Bd73FWUAdhk+mBHgvC4b3KpBQHgmlpyBi5wESqV4bMEIPxXNbb6pNQAeiuIw8jjQo7AfZaAXFM/Th3mYE6r/mtgCFSgcFZDGbQKBgQC/edOgUjkY1BtrxXF4r7o5xfK1XYlUsGojJn+VUuqzITb86G1M8E3ZZgEsatZJxsZzioO86nf5i549eI6bYiHeE4S9J3sVQnLfjc9l5G6uyXROBVevgP6gKo452aQ5bYCbIIZnjdWNekVaSO97VhJ/bEg+6gHZxoB3+pYwYwPazQKBgQCCrDAm/uMMiXSNkwyw9jQy3yOu3LnjHKSaVN0Z8dwkUJ5zhZvAwSwO/kPBKQCdjqv/xfXknfewPBRSQxjVhTbhFtMIyLVQx7w/+fo4OosUuCttCwI3szrRjdZ3qSS0JPwIGMwfa5fyt1jMdl1uCymft2h9cKJ1iPe9Um+4JSdukQKBgFgaKzjqfGEjP5bAG60HVm282id/aXAxWDTiQvQnWdygXNfT7m7nZzqvx7xzUDRUJP4G7wTe8eM9zcrFDQEMDz9KxdnvL6Ahmg+pBZQBnrgH897ucGFNvlteGWEe9oSCERnPxmghh/B4IS8gviiG+y3sWfWw4LcesgACqlaLSLvFAoGAVPmzVCLjTLOkIpN7PBqZnKh2q+AyOniKIIKHOta1IJcUSb6en2d4PI5Y8Uxu9NhJ0BrnaYVqTnoy3LKoq0qv2FJU2QeImW1h1YTFMUJOQ95KLbkTn7pvhWsZpeqME9bZgK53h+2R/IaO/bYj+VxkagwIYJjwtNDImmXXRYZFhc4=-----END RSA PRIVATE KEY-----"""

ALIPAY_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApJe5DYcMHhnBXtZJXF96FldXEol4lLwZ98cszNoW+GE+6xHSkFQDuOKfz6djvEMZotcavwPYWWZ8g6aCXhUgEKtFYVsZSE6l88Goe/KS0A1kNahSagEU+0PE/4iSsRffXeOfxrlrhBqxCfuePNcwNZpNZUrCYUCoIsJQ6qMbLDxgnvaNWeOjGa7Cga49lkbu412lsm/uHuT6Bwj4p4Ni5QOOnxbYQ7TK7ot56XwjhfNyuqnOP3Lwv9ejb5/pYK0+ylkZwaz25d4m8+gqRumLJlB9zoj+c/aFQyxOmU5LHhi+gHapCTjMwK1tfIyDbRtZu0vLntgdKrwTq4bpU/BZzQIDAQAB-----END PUBLIC KEY-----"""

def format_private_key(private_key_str):
    """格式化私钥"""
    # 移除现有的头部和尾部
    private_key = private_key_str.replace('-----BEGIN RSA PRIVATE KEY-----', '')
    private_key = private_key.replace('-----END RSA PRIVATE KEY-----', '')
    
    # 移除所有空白字符
    private_key = ''.join(private_key.split())
    
    # 确保是有效的 base64
    try:
        # 尝试解码看是否是有效的 base64
        base64.b64decode(private_key)
    except:
        raise ValueError("Invalid private key content")
    
    # 每64个字符添加换行
    chunks = [private_key[i:i+64] for i in range(0, len(private_key), 64)]
    formatted_key = '\n'.join(chunks)
    
    # 添加头部和尾部
    return f"-----BEGIN RSA PRIVATE KEY-----\n{formatted_key}\n-----END RSA PRIVATE KEY-----"

def format_public_key(public_key_str):
    """格式化公钥"""
    # 移除现有的头部和尾部
    public_key = public_key_str.replace('-----BEGIN PUBLIC KEY-----', '')
    public_key = public_key.replace('-----END PUBLIC KEY-----', '')
    
    # 移除所有空白字符
    public_key = ''.join(public_key.split())
    
    # 确保是有效的 base64
    try:
        # 尝试解码看是否是有效的 base64
        base64.b64decode(public_key)
    except:
        raise ValueError("Invalid public key content")
    
    # 每64个字符添加换行
    chunks = [public_key[i:i+64] for i in range(0, len(public_key), 64)]
    formatted_key = '\n'.join(chunks)
    
    # 添加头部和尾部
    return f"-----BEGIN PUBLIC KEY-----\n{formatted_key}\n-----END PUBLIC KEY-----"

try:
    formatted_private_key = format_private_key(APP_PRIVATE_KEY)
    formatted_public_key = format_public_key(ALIPAY_PUBLIC_KEY)
    
    ALIPAY_CONFIG = {
        'app_id': '9021000142659642',  # 替换为你的应用ID
        'app_notify_url': None,
        'app_private_key_string': formatted_private_key,
        'alipay_public_key_string': formatted_public_key,
        'sign_type': "RSA2",
        'debug': True  # 沙箱模式设置为 True
    }
except Exception as e:
    print(f"格式化密钥时出错: {str(e)}")
    raise

def verify_key_format(key_string):
    """验证密钥格式"""
    try:
        if "PRIVATE KEY" in key_string:
            serialization.load_pem_private_key(
                key_string.encode(),
                password=None,
                backend=default_backend()
            )
        else:
            serialization.load_pem_public_key(
                key_string.encode(),
                backend=default_backend()
            )
        return True
    except Exception as e:
        print(f"密钥验证失败: {str(e)}")
        return False

def get_alipay_client():

    try:
        # 验证密钥格式
        if not verify_key_format(ALIPAY_CONFIG['app_private_key_string']):
            raise ValueError("私钥格式不正确")
        if not verify_key_format(ALIPAY_CONFIG['alipay_public_key_string']):
            raise ValueError("公钥格式不正确")
        
        alipay = AliPay(
            appid=ALIPAY_CONFIG['app_id'],
            app_notify_url=ALIPAY_CONFIG['app_notify_url'],
            app_private_key_string=ALIPAY_CONFIG['app_private_key_string'],
            alipay_public_key_string=ALIPAY_CONFIG['alipay_public_key_string'],
            sign_type=ALIPAY_CONFIG['sign_type'],
            debug=ALIPAY_CONFIG['debug']
        )
        return alipay
    except Exception as e:
        print(f"初始化支付宝客户端失败: {str(e)}")
        raise