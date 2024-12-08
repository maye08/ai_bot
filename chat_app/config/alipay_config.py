from alipay import AliPay
import os

# 支付宝配置
ALIPAY_CONFIG = {
    'app_id': 'your_app_id',  # 支付宝应用ID
    'app_notify_url': None,
    'app_private_key_string': 'your_private_key',  # 应用私钥
    'alipay_public_key_string': 'alipay_public_key',  # 支付宝公钥
    'sign_type': 'RSA2',
    'debug': False  # 默认False, 如果是沙箱模式则设置为True
}

def get_alipay_client():
    return AliPay(
        appid=ALIPAY_CONFIG['app_id'],
        app_notify_url=ALIPAY_CONFIG['app_notify_url'],
        app_private_key_string=ALIPAY_CONFIG['app_private_key_string'],
        alipay_public_key_string=ALIPAY_CONFIG['alipay_public_key_string'],
        sign_type=ALIPAY_CONFIG['sign_type'],
        debug=ALIPAY_CONFIG['debug']
    )