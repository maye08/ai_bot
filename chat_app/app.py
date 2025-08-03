from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from openai import OpenAI
import tiktoken
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import uuid
import traceback
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models.database_models import db, User, ChatHistory, ChatSession
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import random
import string
import base64
from models.model_config import ModelProcessor, MODELS_CONFIG, ModelType
import sys
from utils.exchange_rate import get_exchange_rate_pbc
import time
from urllib.request import urlopen
from urllib.error import URLError
import re
from urllib.parse import urlparse
import stripe
import random
import string
from flask_mail import Mail, Message

stripe.api_key = os.environ.get("STRIPE_API_KEY")
endpoint_secret = os.getenv('STRIPE_ENDPOINT_SECRET')

# 修改这行导入，添加 Subscription 和 PaymentRecord
from models.database_models import (
    db, User, ChatHistory, ChatSession, 
    Subscription, PaymentRecord  # 添加这两个模型的导入
)


# 添加项目根目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# 使用绝对导入
from chat_app.config.alipay_config import get_alipay_client

# 订阅计划配置
SUBSCRIPTION_PLANS = {
    'monthly': {
        'name': '月度订阅',
        'period': '月',
        'interval': 'month',
        'interval_count': 1,
        'price': 0.99,
        'price_id': 'price_1R5xISICJ6vWDmTZkUs6cJz7',
        'points': 100000,
        'duration': 31  # 天数
    },
    'yearly': {
        'name': '年度订阅',
        'period': '年',
        'interval': 'year',
        'interval_count': 1,
        'price': 11.79,
        'price_id': 'price_1R5xINICJ6vWDmTZdTmOEDkW',
        'points': 1200000,
        'duration':365  # 天数
    }
}

def is_valid_image_url(url):
    """简单检查图片URL是否可被下载"""
    try:
        with urlopen(url, timeout=5) as response:
            # 只读取前几个字节就关闭连接
            response.read(1024)
            return True
    except Exception:  # 捕获所有可能的异常
        return False

def is_valid_url(url):
    """检查URL是否有效"""
    if "data:image/" in url:
        return True
    try:
        with urlopen(url, timeout=5) as response:
            return response.getcode() == 200
    except Exception:
        return False

def setup_logger():
    # 创建 logs 目录
    if not os.path.exists('logs'):
        os.mkdir('logs')
        
    # 配置日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 文件处理器
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=1024 * 1024,
        backupCount=10,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)
    
    # 配置根日志器
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

app = Flask(__name__, 
    template_folder='templates',  # 指定模板目录
    static_folder='static'        # 指定静态文件目录
)

# 会话配置
app.config.update(
    SECRET_KEY='your-secret-key',  # 更改为安全的密钥
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)

# 数据库配置
# 使用 instance 目录
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(app.instance_path, "chat.db")}'
# 使用内存数据库
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
db.init_app(app)

# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 检查 API 密钥
api_key = os.getenv('OPENAI_API_KEY')
if not api_key:
    logger.error("OpenAI API key not found!")
    raise ValueError("OpenAI API key not found!")

client = OpenAI(api_key=api_key)

# 设置对话上下文的最大长度
MAX_CONTEXT_LENGTH = 128000

# 系统消息
SYSTEM_MESSAGE = {
    "role": "system",
    "content": """你是一个AI助手。请严格遵守以下规则：
1. 记住并使用当前对话中的所有信息
2. 当用户询问身份相关信息时，从对话历史中查找最新的相关信息
3. 如果找到相关信息，请明确回答
4. 保持对话的连贯性和上下文关联"""
}

SYSTEM_MESSAGE_O = {
    "role": "user",
    "content": """你是一个AI助手。请严格遵守以下规则：
1. 记住并使用当前对话中的所有信息
2. 当用户询问身份相关信息时，从对话历史中查找最新的相关信息
3. 如果找到相关信息，请明确回答
4. 保持对话的连贯性和上下文关联"""
}

SYSTEM_MESSAGE_GEMINI = {
    "role": "user",
    "content": """你是一个AI助手。请严格遵守以下规则：
1. 记住并使用当前对话中的所有信息
2. 当用户询问身份相关信息时，从对话历史中查找最新的相关信息
3. 如果找到相关信息，请明确回答
4. 保持对话的连贯性和上下文关联"""
}

def num_tokens_from_messages(messages, model="gpt-3.5-turbo"):
    """计算消息的 token 数量"""
    encoding = tiktoken.encoding_for_model(model)
    num_tokens = 0
    for message in messages:
        num_tokens += 4
        for key, value in message.items():
            num_tokens += len(encoding.encode(str(value)))
            if key == "name":
                num_tokens += -1
    num_tokens += 2
    return num_tokens

def trim_messages(messages, max_context_length):
    """保留系统消息和最近的对话"""
    while messages and num_tokens_from_messages(messages) > max_context_length:
        # 找到第一个非系统消息
        for i, msg in enumerate(messages):
            if msg['role'] != 'system':
                messages.pop(i)  # 删除最早的非系统消息
                break
        else:  # 如果没有找到非系统消息
            break
    return messages

def clean_messages(messages, model_id):
    """清理消息列表中的无效链接"""
    if not messages:
        return messages
    
    # URL正则表达式模式
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+' 
    cleaned_messages = []
    
    for message in messages:
        # 跳过系统消息
        if message.get('role') == 'system':
            if model_id == 'o1-preview' or model_id == 'o1-mini':
                continue
            cleaned_messages.append(message)
            continue
            
        content = message.get('content', '')
        should_keep = True
        
        # 处理不同类型的content
        if isinstance(content, str):
            # 查找文本中的所有URL
            urls = re.findall(url_pattern, content)
            for url in urls:
                if not is_valid_url(url):
                    should_keep = False
                    break
                    
        elif isinstance(content, list):
            # 处理多模态消息
            for item in content:
                if isinstance(item, dict):
                    if item.get('type') == 'image_url':
                        url = item.get('image_url', {}).get('url', '')
                        if url and not is_valid_url(url):
                            should_keep = False
                            break
                    elif item.get('type') == 'text':
                        urls = re.findall(url_pattern, item.get('text', ''))
                        for url in urls:
                            if not is_valid_url(url):
                                should_keep = False
                                break
                        if not should_keep:
                            break
        
        if should_keep:
            cleaned_messages.append(message)
    
    return cleaned_messages

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.before_request
def before_request():
    """请求预处理：检查会话是否过期"""
    # 添加 get_captcha 到白名单
    logger.error(f"request endpoint is {request.endpoint}")
    logger.error(f"request path is {request.path}")
    if request.endpoint in ['stripe_webhook', 'static', 'login', 'register', 'logout', 'get_captcha', 'send_reset_code', 'verify_reset_code', 'reset_password']:
        return
    
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": "请先登录"}), 401
        return redirect(url_for('login'))

@app.route('/')
@login_required
def chat():
    """聊天页面"""
    subscription = Subscription.query.filter_by(
        user_id=current_user.chat_id,
        status='active'
    ).first()
    return render_template('chat.html', subscription=subscription)

@app.route('/get_chat_history')
@login_required
def get_chat_history():
    """获取聊天历史"""
    try:
        chat_history = ChatHistory.query.filter_by(user_id=current_user.chat_id).first()
        if not chat_history:
            return jsonify({"error": "聊天历史不存在"}), 404
            
        return jsonify({
            "messages": chat_history.messages,
            "current_tokens": num_tokens_from_messages(chat_history.messages),
            "max_tokens": MAX_CONTEXT_LENGTH
        })
        
    except Exception as e:
        logger.error(f"Error getting chat history: {str(e)}")
        return jsonify({"error": "获取聊天历史失败"}), 500

# 初始化模型处理器
model_processor = ModelProcessor(client)

@app.route('/get_models')
@login_required
def get_models():
    """获取支持的模型列表"""
    return jsonify({
        model_id: {
            "name": model_id,
            "type": config.model_type.value
        }
        for model_id, config in MODELS_CONFIG.items()
    })

@app.route('/chat', methods=['POST'])
@login_required
def chat_message():
    # 在处理消息前检查积分
    required_points = 10  # 每次对话消耗的积分
    if not check_points(current_user.chat_id, required_points):
        return jsonify({
            "error": "积分不足，请订阅以获取更多积分",
            "code": "INSUFFICIENT_POINTS"
        }), 403
    """处理聊天请求"""    
    try:
        session_id = request.json.get('session_id')
        chat_session = ChatSession.query.filter_by(
            id=session_id,
            user_id=current_user.chat_id
        ).first()
        
        if not chat_session:
            return jsonify({"error": "对话不存在"}), 404
            
        user_message = request.json.get('message', '')
        model_id = request.json.get('model', 'gpt-4o-mini')
        message_type = request.json.get('type', 'text')  # 添加这行来获取消息类型

        if model_id not in MODELS_CONFIG:
            return jsonify({"error": f"不支持的模型: {model_id}"}), 400

        model_config = MODELS_CONFIG[model_id]
        
        try:
            if model_config.model_type == ModelType.GEMINI:
                current_messages = chat_session.messages.copy() if isinstance(chat_session.messages, list) else [SYSTEM_MESSAGE_GEMINI]
                # 处理 Gemini 格式的消息
                if current_messages and len(current_messages) > 0:
                    # 转换历史消息为 Gemini 格式
                    gemini_messages = []
                    for msg in current_messages:
                        if msg['role'] != 'system':  # 跳过系统消息
                            gemini_messages.append({
                                "role": "user" if msg['role'] == "user" else "model",
                                "parts": [{msg['content']}]
                            })
                else:
                    gemini_messages = []

                # 添加新的用户消息
                gemini_messages.append({
                    "role": "user",
                    "parts": [{user_message}]
                })

                response = model_processor.process_gemini(
                    messages=gemini_messages,
                    model_id=model_id,
                    user_id=current_user.chat_id,  # 添加用户ID
                    **model_config.params
                )
                
                if response.get("type") != 'error':
                    # 保存 Gemini 响应到历史记录
                    current_messages.append({
                        "role": "assistant",
                        "content": response["content"],
                        "type": "text"
                    })
                else:
                    current_messages.append({
                        "role": "system",
                        "content": "服务器返回错误",
                        "type": "error"
                    })
                chat_session.messages = current_messages
                chat_session.last_message = user_message
                chat_session.last_updated = datetime.utcnow()
                db.session.commit()
                # 消息处理成功后扣除积分
                required_points = calculate_points(model_id, response)
                if not deduct_points(current_user.chat_id, required_points):
                    return jsonify({
                        "error": "扣除积分失败",
                        "code": "POINTS_DEDUCTION_FAILED"
                    }), 500
            
                # 获取最新积分
                subscription = Subscription.query.filter_by(
                    user_id=current_user.chat_id,
                    status='active'
                ).first()
            
                return jsonify({
                    "response": response,
                    "current_tokens": num_tokens_from_messages(current_messages),
                    "max_tokens": MAX_CONTEXT_LENGTH,
                    "points_remaining": subscription.points if subscription else 0
                })


            elif model_config.model_type == ModelType.TEXT:
                if model_id == 'o1-preview' or model_id == 'o1-mini':
                    current_messages = chat_session.messages.copy() if isinstance(chat_session.messages, list) else [SYSTEM_MESSAGE_O]
                else:
                    current_messages = chat_session.messages.copy() if isinstance(chat_session.messages, list) else [SYSTEM_MESSAGE]
                # 提取除了最后一条图片消息外的所有文本内容

                # 处理图片消息
                if message_type == 'image':

                    # 提取除了最后一条图片消息外的所有文本内容
                    previous_text = ""
                    if current_messages and len(current_messages) > 1:
                        for msg in current_messages[:-1]:  # 排除最后一条（图片消息）
                            if msg['role'] != 'system':  # 排除系统消息
                                content = msg.get('content', '')
                                if isinstance(content, str):  # 处理文本消息
                                    previous_text += content + "\n"
                                elif isinstance(content, list):  # 处理可能的多模态消息
                                    for item in content:
                                        if isinstance(item, dict) and item.get('type') == 'text':
                                            previous_text += item.get('text', '') + "\n"


                    # 移除最后一条消息（原始图片消息）
                    if len(current_messages) > 1:
                        current_messages.pop()
                    # 提取图片内容
                    # 提取图片内容和纯文本内容
                    image_content = []
                    text_content = []
                    for line in user_message.split('\n'):
                        if line.startswith('![') and '](' in line and line.endswith(')'):
                            # 提取图片URL
                            image_url = line[line.index('(')+1:-1]
                            if is_valid_image_url(image_url):
                                image_content.append({
                                    "type": "image_url",
                                    "image_url": {
                                        "url": image_url
                                    }
                                })
                        else:
                            # 保存非图片的文本内容
                            line = line.strip()
                            if line:  # 只保存非空行
                                text_content.append(line)
                    # 合并所有文本内容
                    user_text = "\n".join(text_content)
                    # 构建上下文文本
                    context_text = "请结合以下内容分析这张图片："
                    if previous_text.strip():
                        #context_text += "\n历史对话：" + previous_text
                        pass
                    if user_text.strip():
                        context_text += "\n用户描述：" + user_text

            
                    # 构建带图片的消息
                    if image_content:
                        current_messages.append({
                            "role": "user",
                            "content": [
                                {"type": "text", "text": context_text},
                                *image_content
                            ]
                        })
                    else:
                        current_messages.append({
                            "role": "user",
                            "content": user_text
                        })

                else:# message type is TEXT
                    if current_messages and len(current_messages) > 1:
                        msg = current_messages[-1] # 最后一条消息是AI生成的图片
                        if msg['role'] == 'assistant' and msg['type'] == 'image':
                            # 构建图片消息
                            # 提取图片URL
                            image_url = msg.get('content', '')
                            image_content = []
                            if is_valid_image_url(image_url):
                                image_content.append({
                                    "type": "image_url",
                                    "image_url": {
                                        "url": image_url
                                    }
                                })
                                # 构建带图片的消息
                                current_messages.append({
                                    "role": "user",
                                    "content": [
                                        {"type": "text", "text": user_message},
                                        *image_content
                                    ]
                                })
                            else:
                                # 处理普通文本消息
                                current_messages.append({
                                    "role": "user",
                                    "content": user_message
                                })
                            
                        else:        
                            # 检查user_message是否为列表格式
                            if isinstance(user_message, list):
                                # 处理列表格式的消息
                                message_content = []
                                for item in user_message:
                                    if isinstance(item, dict):
                                        # 处理图片URL
                                        if 'image_url' in item:
                                            url = item['image_url'].get('url', '')
                                            if is_valid_image_url(url):
                                                message_content.append({
                                                    "type": "image_url",
                                                    "image_url": {"url": url}
                                                })
                                        # 处理文本内容
                                        elif 'text' in item:
                                            message_content.append({
                                                "type": "text",
                                                "text": item['text']
                                            })
                                
                                # 添加处理后的消息
                                if message_content:
                                    current_messages.append({
                                        "role": "user",
                                        "content": message_content
                                    })
                            else:
                                # 处理普通文本消息
                                if current_messages and len(current_messages) > 1:
                                # 清理无效链接
                                    current_messages = clean_messages(current_messages, model_id)
                                current_messages.append({
                                    "role": "user",
                                    "content": user_message
                                })
                    else:
                        # 处理普通文本消息
                        if current_messages and len(current_messages) > 1:
                                # 清理无效链接
                                current_messages = clean_messages(current_messages, model_id)
                        current_messages.append({
                            "role": "user",
                            "content": user_message
                        })
                params = model_config.params.copy()
                if 'max_completion_tokens' in params:
                    params['max_completion_tokens'] = params.pop('max_completion_tokens')
                
                current_messages = clean_messages(current_messages, model_id)
                response = model_processor.process_text(
                    messages=current_messages,
                    model_id=model_id,
                    **params
                )
                
                if response.get("type") != 'error':
                    current_messages.append({"role": "assistant", "content": response["content"], "type": "text"})
                else:
                    current_messages.append({"role": "system", "content": "服务器返回错误", "type": "error"})
                chat_session.messages = current_messages
                chat_session.last_message = user_message  # 更新最后一条消息
                chat_session.last_updated = datetime.utcnow()
                db.session.commit()

                # 消息处理成功后扣除积分
                # 计算并扣除积分
                required_points = calculate_points(model_id, response)
                if not deduct_points(current_user.chat_id, required_points):
                    return jsonify({
                        "error": "扣除积分失败",
                        "code": "POINTS_DEDUCTION_FAILED"
                    }), 500
                
                # 获取最新积分
                subscription = Subscription.query.filter_by(
                    user_id=current_user.chat_id,
                    status='active'
                ).first()
                
                return jsonify({
                    "response": response,
                    "current_tokens": num_tokens_from_messages(current_messages),
                    "max_tokens": MAX_CONTEXT_LENGTH,
                    "points_remaining": subscription.points if subscription else 0
                })
            
            elif model_config.model_type == ModelType.IMAGE:
                required_points = 500
                if not check_points(current_user.chat_id, required_points):
                    return jsonify({
                        "error": "积分不足，请订阅以获取更多积分",
                        "code": "INSUFFICIENT_POINTS"
                    }), 403
                # 开始事务
                db.session.begin_nested()
                try:
                    # 重新查询会话以确保数据最新
                    chat_session = db.session.query(ChatSession).filter_by(
                        id=session_id,
                        user_id=current_user.chat_id
                    ).with_for_update().first()
                
                    if not chat_session:
                        return jsonify({"error": "对话不存在"}), 404
                
                    # 创建新的消息列表
                    if model_id == 'o1-mini' or model_id == 'o1-preview':
                        new_messages = list(chat_session.messages) if chat_session.messages else [SYSTEM_MESSAGE_O]
                    else:
                        new_messages = list(chat_session.messages) if chat_session.messages else [SYSTEM_MESSAGE]
                
                    # 添加用户消息
                    new_messages.append({
                        "role": "user",
                        "content": user_message,
                        "type": "text"
                    })
                
                    # 生成图片
                    response = model_processor.process_image(
                        prompt=user_message,
                        model_id=model_id,
                        **model_config.params
                    )
                
                    # 添加AI响应
                    if response.get("type") == 'error':
                        new_messages.append({
                            "role": "system",
                            "content": response.get("content"),
                            "type": "error"
                        })
                    else:
                        new_messages.append({
                            "role": "assistant",
                            "content": response.get("content"),
                            "type": "image"
                        })
                
                    # 更新会话
                    chat_session.messages = new_messages
                    chat_session.last_message = user_message
                    chat_session.last_updated = datetime.utcnow()
                
                    # 验证数据
                    logger.debug(f"Updating messages to: {new_messages}")
                
                    # 保存更改
                    db.session.flush()
                
                    # 验证保存的数据
                    saved_messages = chat_session.messages
                    if saved_messages != new_messages:
                        raise ValueError("Messages not saved correctly")
                
                    # 提交事务
                    db.session.commit()
                
                    logger.debug(f"Final saved messages: {chat_session.messages}")
                    
                    # 消息处理成功后扣除积分
                    # 计算并扣除积分
                    required_points = calculate_points(model_id, response)
                    if not deduct_points(current_user.chat_id, required_points):
                        return jsonify({
                            "error": "扣除积分失败",
                            "code": "POINTS_DEDUCTION_FAILED"
                        }), 500
                
                    # 获取最新积分
                    subscription = Subscription.query.filter_by(
                        user_id=current_user.chat_id,
                        status='active'
                    ).first()
                
                    return jsonify({
                        "response": response,
                        "points_remaining": subscription.points if subscription else 0
                    })
                
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error saving chat messages: {str(e)}")
                    raise


                
        except Exception as e:
            logger.error(f"Chat error: {str(e)}")
            return jsonify({
                "response": {
                    "type": "error",
                    "content": "处理失败",
                    "status": "error"
                }
            }), 500
            
    except Exception as e:
        logger.error(f"Chat error for user {current_user.chat_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "服务器错误"}), 500

@app.route('/clear_chat', methods=['POST'])
@login_required
def clear_chat():
    """清除聊天历史"""
    try:
        chat_history = ChatHistory.query.filter_by(user_id=current_user.chat_id).first()
        if not chat_history:
            return jsonify({"error": "Chat history not found"}), 404
            
        # 只保留系统消息
        chat_history.messages = [SYSTEM_MESSAGE]
        chat_history.last_updated = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            "message": "Chat history cleared successfully",
            "current_tokens": num_tokens_from_messages([SYSTEM_MESSAGE]),
            "max_context_length": MAX_CONTEXT_LENGTH
        })
        
    except Exception as e:
        logger.error(f"Error clearing chat history: {str(e)}")
        return jsonify({"error": "清除聊天历史失败"}), 500

# 生成验证码图片
def generate_captcha():
    # 生成随机字符串
    chars = string.ascii_letters + string.digits
    code = ''.join(random.choices(chars, k=4))
    
    # 创建图片
    width = 120
    height = 40
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    
    try:
        # 尝试使用系统字体
        font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 24)
    except:
        try:
            # Windows 系统字体
            font = ImageFont.truetype('arial.ttf', 24)
        except:
            # 如果都失败了，使用默认字体
            font = ImageFont.load_default()
    
    # 添加干扰线
    for i in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill='gray')
    
    # 添加噪点
    for _ in range(30):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill='black')
    
    # 添加验证码文字
    for i, char in enumerate(code):
        x = 20 + i * 20
        y = random.randint(5, 15)
        # 随机颜色
        color = (random.randint(0, 100), random.randint(0, 100), random.randint(0, 100))
        draw.text((x, y), char, font=font, fill=color)
    
    # 转换为base64
    buffer = BytesIO()
    image.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return code, f'data:image/png;base64,{img_str}'

@app.route('/get_captcha')
def get_captcha():
    try:
        code, image = generate_captcha()
        session['captcha'] = code
        return jsonify({'image': image})
    except Exception as e:
        logger.error(f"Error generating captcha: {str(e)}")
        return jsonify({"error": "验证码生成失败"}), 500

# 修改登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('chat'))
        return render_template('login.html')
    
    data = request.json
    captcha = data.get('captcha', '').upper()
    if 'captcha' not in session or captcha != session['captcha'].upper():
        return jsonify({"error": "验证码错误"}), 400
        
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        login_user(user)
        session.pop('captcha', None)  # 清除验证码
        return jsonify({"redirect_url": url_for('chat')})
    
    return jsonify({"error": "用户名或密码错误"}), 401

# 修改注册路由
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    captcha = data.get('captcha', '').upper()
    if 'captcha' not in session or captcha != session['captcha'].upper():
        return jsonify({"error": "验证码错误"}), 400
    
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({"error": "用户名已存在"}), 400
        
    try:
        # 创建新用户
        user = User(username=data.get('username'), email=data.get('email'))
        user.set_password(data.get('password'))
        
        chat_history = ChatHistory(
            user_id=user.chat_id,
            messages=[SYSTEM_MESSAGE]
        )
        
        db.session.add(user)
        db.session.add(chat_history)

        # 添加默认订阅计划
        subscription = Subscription(
            user_id=user.chat_id,
            user_email=user.email,
            plan_type='free',
            points=100000,  # 默认赠送的积分
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
            status='active'
        )

        db.session.add(subscription)
        db.session.commit()
        
        login_user(user)
        session.pop('captcha', None)  # 清除验证码
        return jsonify({"redirect_url": url_for('chat')})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "注册失败"}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))  # 使用 url_for

def is_ajax_request():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'

@app.errorhandler(404)
def page_not_found(e):
    if is_ajax_request():
        return jsonify({"error": "页面不存在"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    if is_ajax_request():
        return jsonify({"error": "服务器内部错误"}), 500
    return render_template('500.html'), 500

@app.route('/create_chat_session', methods=['POST'])
@login_required
def create_chat_session():
    try:
        session = ChatSession(
            user_id=current_user.chat_id,
            messages=[SYSTEM_MESSAGE]
        )
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            "session_id": session.id
        })
    except Exception as e:
        logger.error(f"Error creating chat session: {str(e)}")
        return jsonify({"error": "创建对话失败"}), 500

@app.route('/get_chat_sessions')
@login_required
def get_chat_sessions():
    try:
        sessions = ChatSession.query.filter_by(
            user_id=current_user.chat_id
        ).order_by(ChatSession.last_updated.desc()).all()
        
        return jsonify({
            "sessions": [{
                "id": session.id,
                "last_message": session.last_message
            } for session in sessions]
        })
    except Exception as e:
        logger.error(f"Error getting chat sessions: {str(e)}")
        return jsonify({"error": "获取对话列表失败"}), 500

@app.route('/get_chat_session/<int:session_id>')
@login_required
def get_chat_session(session_id):
    try:
        session = ChatSession.query.filter_by(
            id=session_id,
            user_id=current_user.chat_id
        ).first()

        # 添加调试日志
        logger.debug(f"Retrieved messages for session {session_id}: {session.messages}")
        
        if not session:
            return jsonify({"error": "对话不存在"}), 404
            
        return jsonify({
            "messages": session.messages,
            "current_tokens": num_tokens_from_messages(session.messages),
            "max_context_length": MAX_CONTEXT_LENGTH
        })
    except Exception as e:
        logger.error(f"Error getting chat session: {str(e)}")
        return jsonify({"error": "获取对话失败"}), 500

@app.route('/clear_chat_session/<int:session_id>', methods=['POST'])
@login_required
def clear_chat_session(session_id):
    try:
        chat_session = ChatSession.query.filter_by(
            id=session_id,
            user_id=current_user.chat_id
        ).first()
        
        if not chat_session:
            return jsonify({"error": "对话不存在"}), 404
        
        # 删除对话
        db.session.delete(chat_session)
        db.session.commit()
        
        return jsonify({
            "message": "对话已清除",
            "current_tokens": 0,
            "max_context_length": MAX_CONTEXT_LENGTH
        })
        
    except Exception as e:
        logger.error(f"Error clearing chat session: {str(e)}")
        return jsonify({"error": "清除对话失败"}), 500

@app.route('/get_image_count/<int:session_id>')
@login_required
def get_image_count(session_id):
    """获取会话中生成的图片数量"""
    try:
        chat_session = ChatSession.query.filter_by(
            id=session_id,
            user_id=current_user.chat_id
        ).first()
        
        if not chat_session:
            return jsonify({"count": 0})
            
        # 计算图片消息的数量
        image_count = sum(1 for msg in chat_session.messages 
                         if msg.get('role') == 'assistant' and msg.get('type') == 'image')
        
        return jsonify({"count": image_count})
        
    except Exception as e:
        logger.error(f"Error getting image count: {str(e)}")
        return jsonify({"count": 0})

@app.route('/subscription')
@login_required
def subscription_page():
    """订阅页面"""
    subscription = Subscription.query.filter_by(
        user_id=current_user.chat_id,
        status='active'
    ).first()

    logger.debug(f"User {current_user.username} subscription info: {subscription.__dict__ if subscription else None}")
    logger.debug(f"Available plans: {SUBSCRIPTION_PLANS}")
    
    return render_template('subscription.html', 
        plans=SUBSCRIPTION_PLANS,
        subscription=subscription,
        SUBSCRIPTION_PLANS=SUBSCRIPTION_PLANS
    )

@app.route('/create_order', methods=['POST'])
@login_required
def create_order():
    user = current_user
    if not user.is_authenticated:
        return jsonify({'error': '未登录'}), 401

    plan_type = request.json.get('plan_type')
    if plan_type not in SUBSCRIPTION_PLANS:
        return jsonify({'error': '无效的订阅类型'}), 400

    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=user.email,  # 使用用户的email
            payment_method_types=['card','wechat_pay','alipay','amazon_pay','paypal'],
            payment_method_options={
                'wechat_pay': {
                    'client': 'web'
                }
            },
            line_items=[
                {
                    'price': SUBSCRIPTION_PLANS[plan_type]['price_id'], #### here
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=request.host_url + 'subscription?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'subscription',
            metadata={'plan_type': plan_type}
        )
        return jsonify({'payment_url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/payment/notify', methods=['POST'])
def payment_notify():
    """支付宝异步通知处理"""
    try:
        # 获取支付宝POST过来的数据
        data = request.form.to_dict()
        
        # 验证签名
        alipay = get_alipay_client()
        signature = data.pop("sign")
        success = alipay.verify(data, signature)
        
        if success and data["trade_status"] in ("TRADE_SUCCESS", "TRADE_FINISHED"):
            # 获取订单号
            order_id = data.get('out_trade_no')
            trade_no = data.get('trade_no')  # 支付宝交易号
            
            # 更新支付记录
            payment = PaymentRecord.query.filter_by(order_id=order_id).first()
            if payment and payment.status == 'pending': # 只处理待支付的订单
                payment.status = 'paid'
                payment.trade_no = trade_no
                payment.paid_at = datetime.now()
                
                # 更新用户订阅
                subscription = Subscription.query.filter_by(
                    user_id=payment.user_id,
                    status='active'
                ).first()
                
                if not subscription:
                    subscription = Subscription(
                        user_id=payment.user_id,
                        plan_type=payment.plan_type,  # 使用订单中记录的计划类型,
                        points=SUBSCRIPTION_PLANS[payment.plan_type]['points'],  # 或其他适当的积分数量
                        start_date=datetime.now(),
                        end_date=datetime.now() + timedelta(days=SUBSCRIPTION_PLANS[payment.plan_type]['duration']),
                        status='active'
                    )
                    db.session.add(subscription)
                else:
                    subscription.plan_type = payment.plan_type
                    # 如果是免费用户首次订阅
                    if subscription.plan_type == 'free':
                        subscription.points = SUBSCRIPTION_PLANS[payment.plan_type]['points']
                        subscription.end_date = datetime.now() + timedelta(days=SUBSCRIPTION_PLANS[payment.plan_type]['duration'])
                    else:
                        subscription.points += SUBSCRIPTION_PLANS[payment.plan_type]['points']
                        subscription.end_date = max(
                            subscription.end_date,
                            datetime.now()
                        ) + timedelta(days=SUBSCRIPTION_PLANS[payment.plan_type]['duration'])
                
                db.session.commit()
                logger.info(f"Payment {order_id} processed successfully via notify")
                
            return 'success'
        
        return 'fail'
        
    except Exception as e:
        logger.error(f"处理支付回调时出错: {str(e)}")
        return 'fail'

@app.route('/payment_callback')
def payment_callback():
    """支付完成回调"""
    try:
        alipay = get_alipay_client()
        data = request.args.to_dict()
        signature = data.pop("sign")
        
        # 验证签名
        if alipay.verify(data, signature):
            order_id = data.get('out_trade_no')
            payment = PaymentRecord.query.filter_by(order_id=order_id).first()
            
            if payment and payment.status == 'pending':
                payment.status = 'success'
                payment.payment_time = datetime.now()
                
                # 创建或更新订阅
                subscription = Subscription.query.filter_by(
                    user_id=payment.user_id,
                    status='active'
                ).first()
                
                if subscription:
                    subscription.points += SUBSCRIPTION_PLANS[payment.plan_type]['points']
                    subscription.plan_type = payment.plan_type  # 添加这行
                else:
                    subscription = Subscription(
                        user_id=payment.user_id,
                        plan_type=payment.plan_type,
                        points=SUBSCRIPTION_PLANS[payment.plan_type]['points'],
                        start_date=datetime.now(),
                        end_date=datetime.now() + timedelta(days=SUBSCRIPTION_PLANS[payment.plan_type]['duration'])
                    )
                    db.session.add(subscription)
                
                db.session.commit()
                return redirect(url_for('subscription_page'))
                
        return jsonify({'error': '支付验证失败'}), 400
        
    except Exception as e:
        logger.error(f"支付回调处理失败: {str(e)}")
        return jsonify({'error': '支付处理失败'}), 500    

def check_points(user_id, required_points):
    """检查用户积分是否足够"""
    subscription = Subscription.query.filter_by(
        user_id=user_id,
        status='active'
    ).first()
    
    if not subscription or subscription.points < required_points:
        return False
    return True

def deduct_points(user_id, points):
    """扣除用户积分"""
    try:
        subscription = Subscription.query.filter_by(
            user_id=user_id,
            status='active'
        ).first()
        
        if subscription:
            subscription.points -= points
            db.session.commit()
            return True
        return False
    except Exception as e:
        logger.error(f"扣除积分失败: {str(e)}")
        db.session.rollback()
        return False

def calculate_points(model_id: str, response_data: dict) -> int:
    """计算需要扣除的积分"""
    model_config = MODELS_CONFIG.get(model_id)
    if not model_config:
        raise ValueError(f"未知的模型: {model_id}")
    if model_config.model_type == ModelType.GEMINI:
        input_tokens = response_data.get('input_tokens', 0)
        output_tokens = response_data.get('output_tokens', 0)
        points = (
            (input_tokens * model_config.input_price / 1000 + 
             output_tokens * model_config.output_price / 1000)
            * 100000
        )
    elif model_config.model_type == ModelType.TEXT:
        input_tokens = response_data.get('input_tokens', 0)
        output_tokens = response_data.get('output_tokens', 0)
        points = (
            (input_tokens * model_config.input_price / 1000 + 
             output_tokens * model_config.output_price / 1000)
            * 100000
        )
    else:  # IMAGE
        points = model_config.output_price * 100000
        
    return int(points)

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    #payload = request.get_data(as_text=True)
    payload = request.data
    logger.info(f"Stripe webhook payload: {payload}")
    sig_header = request.headers.get('Stripe-Signature')
    logger.info(f"Stripe webhook sig_header: {sig_header}")
    logger.info(f"Stripe webhook endpoint secret: {endpoint_secret}")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        logger.info(f"received event = {event}")
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({'error': str(e)}), 400
    
    email_from_webhook = event['data']['object']['customer_email']
    # 处理付款成功事件
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        plan_type = session.metadata.get('plan_type')

        # 更新用户订阅信息
        subscription = Subscription.query.filter_by(
            user_email=email_from_webhook,
            status='active'
        ).first()

        if not subscription:
            subscription = Subscription(
                user_email=email_from_webhook,
                plan_type=plan_type,
                points=SUBSCRIPTION_PLANS[plan_type]['points'],
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=SUBSCRIPTION_PLANS[plan_type]['duration'])
            )
        else:
            subscription.plan_type = plan_type
            subscription.points += SUBSCRIPTION_PLANS[plan_type]['points']
            subscription.end_date = max(subscription.end_date, datetime.utcnow()) + timedelta(days=SUBSCRIPTION_PLANS[plan_type]['duration'])

        db.session.add(subscription)
        db.session.commit()

    return jsonify({'success': True})

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
# 配置邮件发送
app.config['MAIL_SERVER'] = 'smtp.larksuite.com'  # 使用你的邮件服务器
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
mail = Mail(app)

# 存储验证码（实际应用中应该使用 Redis）
reset_codes = {}

@app.route('/send_reset_code', methods=['POST'])
def send_reset_code():
    try:
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({"error": "该邮箱未注册"}), 400
            
        # 生成6位随机验证码
        code = ''.join(random.choices(string.digits, k=6))
        reset_codes[email] = {
            'code': code,
            'timestamp': datetime.utcnow()
        }
        
        # 发送验证码邮件
        msg = Message(
            '密码重置验证码',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'您的密码重置验证码是：{code}，有效期为5分钟。'
        mail.send(msg)
        
        return jsonify({"message": "验证码已发送"}), 200
        
    except Exception as e:
        logger.error(f"发送验证码失败: {str(e)}")
        return jsonify({"error": "发送验证码失败"}), 500

@app.route('/verify_reset_code', methods=['POST'])
def verify_reset_code():
    email = request.json.get('email')
    code = request.json.get('code')
    
    stored = reset_codes.get(email)
    if not stored:
        return jsonify({"error": "请先获取验证码"}), 400
        
    if datetime.utcnow() - stored['timestamp'] > timedelta(minutes=5):
        del reset_codes[email]
        return jsonify({"error": "验证码已过期"}), 400
        
    if stored['code'] != code:
        return jsonify({"error": "验证码错误"}), 400
        
    return jsonify({"message": "验证成功"}), 200

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        email = request.json.get('email')
        code = request.json.get('code')
        new_password = request.json.get('new_password')
        
        # 再次验证验证码
        stored = reset_codes.get(email)
        if not stored or stored['code'] != code:
            return jsonify({"error": "验证码无效"}), 400
            
        # 更新密码
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "用户不存在"}), 400
            
        user.set_password(new_password)
        db.session.commit()
        
        # 清除验证码
        del reset_codes[email]
        
        return jsonify({"message": "密码修改成功"}), 200
        
    except Exception as e:
        logger.error(f"重置密码失败: {str(e)}")
        return jsonify({"error": "重置密码失败"}), 500

if __name__ == '__main__':
    with app.app_context():
        # 只在首次运行时创建表
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000) 
