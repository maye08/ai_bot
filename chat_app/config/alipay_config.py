from alipay import AliPay
import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 支付宝配置
# 注意：每行之间要有换行符，且内容要正确对齐

APP_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClJoXMEfkV8UOceiXMPCLSpz4wYMcd22NloRi5TTVQ2DlfW4z1I93etOim+BAeyLne8PlgQKt7aBFUdS5iWplkDF3hWW9b/PVQrgcgzVQVXRT8Vr57dysAF4v+lyl+EIgvVu2uSPFg3k4TzJ53Mm1OYu9QDyw8rrSBSyGURHjf62GiP9uQsNKyL9C/CCSFbPDX3r9VgKAdg3m3E+XPfUIPms1MGTU/7OB71LY+tq4LwXaO5N6br2rcvcDX/TT8vIay4tBeQ9NY0DoC+7dJdjdYNWxSv2IYC6hyiRhsH7SjgtwlZmoUr53mCxgIL3M0Tnqv7bPJy8KGUwIzDX2tuVJPAgMBAAECggEAVoxGp/hvSfGDFjjpIAwPz8d3jtDY6Ku1fmgbVdjBbRmzj2aiC0H9nx29ourzP76/sbclaSza8TRLiLBUW5TROB5HALbm5hU91kctUyJnwz5hphAriPadoVG1uvkq9Hbjd7Odoa12WeaGkle0YBEcOW0drx4Ud8SyseNWuKXdlrKi2KvKPgfdCU9tqG2hupsiwBDVY4C82gW93JzeMMyG/3+In5vMRUAOHKr3+XTiJ0nvTaOdn/xEuWTZfapQGvg+GDfw5wCq5sOn98VeZncy1xFwhN8xsv90UQAMBV+Mp51LDcu1OI35Qk7NLVUQNgQAsjCj2Jkt7Q9y4PnbhV/rGQKBgQDfcy1MH0A8HK3aLYDjOsCi2BdDxiq/Q7Njpc4pFZ/ogqiHvcKBTaa67CIIjn6siN6byly+mJqFhd7HnMcBgIrD4Lm4ZuWPhBwvY/NsUOss5txYqmiA3/fTHBmuIZJijQ6EdC6Df1U5AmcXIWnwePjKfhrC7cnfMEkg/JaP0S9hXQKBgQC9NUMIa1WY+5smU23DD2i54EwtysktnJNcc2sW7TsRUsIav3ag2126T5waiF83NubUmWHmbVfuCliijg/aZyZXYt4up++/nrgIAHNlGPwmS6jZpmN8v4bA29UwXWIrp6HQJQeMRX/UD2qNu20PYkw5X10zYfGxy+cC7EtC3r3rmwKBgD/PKUFSr0o7Ol5SnjrFfVtDcClXfr+Nur2bDKto1HhWT4Ar7U51eUZpxjJBVuU4VLGScTewZnf4yayhFadVKMtU8lQ5dhasuEvENDBbTz1MU+IyD5O14ZR0stSqG55u/5VNhDbi9thH2l6dmR4lvY49wrClrP9CT6/O0cQSDYC1AoGAVtbeODwDIl7AW7vI0dD9sOoILLA4221UmQcELJafGJlSKzKbAMMN5pfpPqg+gzn4gbUQINEonUE0Yw8uqX/UMiFXdjRvrhPrxQhn7guklvL8wUBDwxqof1WmKDeD+iNK+hw0taWkQLD+p6RRLtFfyKlDPnUCmCbMlSPcewl+Q2cCgYEAy5mPFXx3NMmSEEBjsXi6hu61Sb2Wbw8Y1zSiMfkKFamzozB1b8HvapopOAOqggtV4eKnP9WG4AH5FMZscU22akoYVX5D3Ps4uC5mU72qHUkJ+vs5ctnH/ZVCtY24jm9fdACWmo8zStBoEyOgdeGoN1ohc4h6BEiQnzFvPB2lZj4=-----END RSA PRIVATE KEY-----"""

ALIPAY_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApSaFzBH5FfFDnHolzDwi0qc+MGDHHdtjZaEYuU01UNg5X1uM9SPd3rTopvgQHsi53vD5YECre2gRVHUuYlqZZAxd4VlvW/z1UK4HIM1UFV0U/Fa+e3crABeL/pcpfhCIL1btrkjxYN5OE8yedzJtTmLvUA8sPK60gUshlER43+thoj/bkLDSsi/QvwgkhWzw196/VYCgHYN5txPlz31CD5rNTBk1P+zge9S2PrauC8F2juTem69q3L3A1/00/LyGsuLQXkPTWNA6Avu3SXY3WDVsUr9iGAuocokYbB+0o4LcJWZqFK+d5gsYCC9zNE56r+2zycvChlMCMw19rblSTwIDAQAB-----END PUBLIC KEY-----"""

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
        'app_id': '2021005106650063',  # 替换为你的应用ID
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