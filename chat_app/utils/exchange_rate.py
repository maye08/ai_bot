import requests
from bs4 import BeautifulSoup
from functools import lru_cache
from datetime import datetime, timedelta

@lru_cache(maxsize=1)
def get_exchange_rate_pbc():
    """
    从中国人民银行获取美元汇率
    """
    try:
        url = "http://www.pbc.gov.cn/rmyh/108976/109428/index.html"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5)
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'html.parser')
        # 解析网页获取汇率
        rate_element = soup.find('td', text='美元')
        if rate_element:
            rate = float(rate_element.find_next_sibling('td').text.strip())
            return rate
        raise ValueError("无法找到汇率数据, 使用默认汇率7.3")
    except Exception as e:
        return 7.3  # 返回默认汇率