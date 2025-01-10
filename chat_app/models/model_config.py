from enum import Enum
from typing import Dict, Any
from openai import OpenAI
import logging
import requests
import time
import google.generativeai as genai
import os

# 添加 Gemini 格式的系统消息
SYSTEM_MESSAGE_GEMINI = """你是一个AI助手。请严格遵守以下规则：
1. 记住并使用当前对话中的所有信息
2. 当用户询问身份相关信息时，从对话历史中查找最新的相关信息
3. 如果找到相关信息，请明确回答
4. 保持对话的连贯性和上下文关联
5. 所有回复必须使用中文"""

class ModelType(Enum):
    TEXT = "text"
    IMAGE = "image"
    GEMINI = "gemini"  # 添加新的模型类型

# 添加logger定义
logger = logging.getLogger(__name__)

# 在 ModelConfig 类中添加价格配置
class ModelConfig:
    def __init__(self, model_id: str, model_type: ModelType, params: Dict[str, Any] = None, 
                 input_price: float = 0, output_price: float = 0):
        self.model_id = model_id
        self.model_type = model_type
        self.params = params or {}
        self.input_price = input_price
        self.output_price = output_price

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
        # 初始化字典
        self.gemini_models = {}  # 存储不同 Gemini 模型实例
        self.gemini_chats = {}   # 存储不同用户的聊天会话

        # 初始化 Gemini
        if os.environ.get("GEMINI_API_KEY"):
            genai.configure(api_key=os.environ["GEMINI_API_KEY"])
            # 初始化所有 Gemini 模型
            for model_id, config in MODELS_CONFIG.items():
                if config.model_type == ModelType.GEMINI:
                    generation_config = {
                        "temperature": config.params.get("temperature", 1.0),
                        "top_p": config.params.get("top_p", 0.95),
                        "top_k": config.params.get("top_k", 40),
                        "max_output_tokens": config.params.get("max_completion_tokens", 8192),
                    }
                    self.gemini_models[model_id] = genai.GenerativeModel(
                        model_name=model_id,
                        generation_config=generation_config,
                        system_instruction=SYSTEM_MESSAGE_GEMINI
                    )

    def get_or_create_chat(self, user_id: str, model_id: str, history: list = None):
        """获取或创建用户的聊天会话"""
        chat_key = f"{user_id}_{model_id}"
        if chat_key not in self.gemini_chats:
            model = self.gemini_models.get(model_id)
            if not model:
                raise ValueError(f"未找到模型: {model_id}")
            self.gemini_chats[chat_key] = model.start_chat(history=history or [])
        return self.gemini_chats[chat_key]
    
    def process_text(self, messages: list, model_id: str, **kwargs) -> dict:
        """处理文本模型请求"""
        try:
            response = self.client.chat.completions.create(
                model=model_id,
                messages=messages,
                **kwargs
            )

            # 获取输入和输出的 token 数量
            input_tokens = response.usage.prompt_tokens
            output_tokens = response.usage.completion_tokens
            
            # 获取响应内容
            content = response.choices[0].message.content
            
            # 格式化数学公式
            formatted_content = format_math_formula(content)
            
            return {
                "type": "text",
                "content": formatted_content,
                "status": "success",
                "input_tokens": input_tokens,
                "output_tokens": output_tokens
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
        
    def process_gemini(self, messages: list, model_id: str, user_id: str, **kwargs) -> dict:
        """处理 Gemini 模型请求"""
        try:
            # 获取或创建聊天会话
            logger.info(f"处理 Gemini 请求: {messages}")
            chat_history = messages[:-1]
            chat = self.get_or_create_chat(user_id, model_id, history=chat_history)
        
            # 发送最新消息，但保持对话历史
            response = chat.send_message(
                messages[-1].get("parts", [{}])[0]
            )
        
            # 格式化数学公式
            formatted_content = format_math_formula(response.text)
        
            return {
                "type": "text",
                "content": formatted_content,
                "status": "success",
                "input_tokens": response.usage_metadata.prompt_token_count,
                "output_tokens": response.usage_metadata.candidates_token_count
            }
            
        except Exception as e:
            logger.error(f"处理 Gemini 请求时出错: {str(e)}")
            return {
                "type": "error",
                "content": f"处理失败: {str(e)}",
                "status": "error"
            }

# 模型配置字典
MODELS_CONFIG = {
    "gpt-3.5-turbo": ModelConfig(
        "gpt-3.5-turbo",
        ModelType.TEXT, 
        {
            "temperature": 0.8,
            "max_completion_tokens": 4000
        },
        input_price=0.003,   # 每1000 tokens的价格
        output_price=0.006
    ),
    "gpt-4o": ModelConfig("gpt-4o", ModelType.TEXT, 
        {
            "temperature": 0.8,
            "max_completion_tokens": 16384
        },
        input_price=0.0025,
        output_price=0.01
    ),
    "dall-e-3": ModelConfig("dall-e-3", ModelType.IMAGE, 
        {
            "size": "1024x1024",
            "quality": "standard",
            "n": 1
        },
        output_price=0.04  # 每张图片的价格
    ),
    "gpt-4o-mini": ModelConfig("gpt-4o-mini", ModelType.TEXT, 
        {
            "temperature": 0.8,
            "max_completion_tokens": 16384
        },
        input_price=0.00015,
        output_price=0.0006
    ),
    "o1-mini": ModelConfig("o1-mini", ModelType.TEXT, 
        {
            "temperature": 1.0,
            "max_completion_tokens": 65536
        },
        input_price=0.003,
        output_price=0.012
    ),
    "o1-preview": ModelConfig("o1-preview", ModelType.TEXT, 
        {
            "temperature": 1.0,
            "max_completion_tokens": 32768
        },
        input_price=0.015,
        output_price=0.06
    ),
    "gemini-2.0-flash-exp": ModelConfig(
        "gemini-2.0-flash-exp",
        ModelType.GEMINI,
        {
            "temperature": 1.0,
            "top_p": 0.95,
            "top_k": 40,
            "max_completion_tokens": 8192,
        },
        input_price=0.0,
        output_price=0.0
    ),
} 