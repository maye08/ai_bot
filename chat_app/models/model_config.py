from enum import Enum
from typing import Dict, Any
from openai import OpenAI
import logging
import requests
import time

# 添加logger定义
logger = logging.getLogger(__name__)

class ModelType(Enum):
    TEXT = "text"
    IMAGE = "image"

class ModelConfig:
    def __init__(self, model_id: str, model_type: ModelType, params: Dict[str, Any] = None):
        self.model_id = model_id
        self.model_type = model_type
        self.params = params or {}

def format_math_formula(content: str) -> str:
    """格式化数学公式，将 LaTeX 公式转换为正确的显示格式"""
    import re
    
    def process_block_formula(match):
        formula = match.group(1).strip()
        return f'\n\\[\n{formula}\n\\]\n'
    
    def process_inline_formula(match):
        formula = match.group(1).strip()
        return f'\\({formula}\\)'
    
    # 处理块级公式
    content = re.sub(r'\\\[([\s\S]*?)\\\]', process_block_formula, content)
    
    # 处理内联公式
    content = re.sub(r'\\\(([\s\S]*?)\\\)', process_inline_formula, content)
    

    return content

class ModelProcessor:
    def __init__(self, client: OpenAI):
        self.client = client

    def process_text(self, messages: list, model_id: str, **kwargs) -> dict:
        """处理文本模型请求"""
        try:
            response = self.client.chat.completions.create(
                model=model_id,
                messages=messages,
                **kwargs
            )
            
            # 获取响应内容
            content = response.choices[0].message.content
            
            # 格式化数学公式
            formatted_content = format_math_formula(content)
            
            return {
                "type": "text",
                "content": formatted_content,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"处理文本请求时出错: {str(e)}")
            return {
                "type": "error",
                "content": f"处理失败: {str(e)}",
                "status": "error"
            }

    def process_image(self, prompt: str, model_id: str, **kwargs) -> dict:
        """处理图像模型请求"""
        try:
            # 生成图片
            response = self.client.images.generate(
                model=model_id,
                prompt=prompt,
                **kwargs
            )
            
            # 验证响应
            if not response.data or not len(response.data):
                raise ValueError("未获取到图片生成结果")
                
            # 获取图片URL
            image_url = response.data[0].url
            if not image_url:
                raise ValueError("图片URL为空")
                
            return {
                "type": "image",
                "content": image_url,
                "status": "success"
            }
                
        except Exception as e:
            logger.error(f"图片生成错误: {str(e)}")
            return {
                "type": "error",  # 改为error类型
                "content": "图片生成失败，请稍后重试",
                "status": "error"
            }

# 模型配置字典
MODELS_CONFIG = {
    "gpt-3.5-turbo": ModelConfig("gpt-3.5-turbo", ModelType.TEXT, {
        "temperature": 0.7,
        "max_tokens": 4000
    }),
    "gpt-4": ModelConfig("gpt-4", ModelType.TEXT, {
        "temperature": 0.7,
        "max_tokens": 4000
    }),
    "dall-e-3": ModelConfig("dall-e-3", ModelType.IMAGE, {
        "size": "1024x1024",
        "quality": "standard",
        "n": 1
    }),
    "gpt-4o-mini": ModelConfig("gpt-4o-mini", ModelType.TEXT, {
        "temperature": 0.7,
        "max_tokens": 4000
    }),
    "o1-mini": ModelConfig("o1-mini", ModelType.TEXT, {
        "temperature": 0.7,
        "max_tokens": 4000
    }),
    "o1-preview": ModelConfig("o1-preview", ModelType.TEXT, {
        "temperature": 0.7,
        "max_tokens": 4000
    })
} 