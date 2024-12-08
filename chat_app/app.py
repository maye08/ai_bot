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

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.before_request
def before_request():
    """请求预处理：检查会话是否过期"""
    # 添加 get_captcha 到白名单
    if request.endpoint in ['static', 'login', 'register', 'logout', 'get_captcha']:
        return
    
    if not current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"error": "请先登录"}), 401
        return redirect(url_for('login'))

@app.route('/')
@login_required
def chat():
    """聊天页面"""
    return render_template('chat.html')

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
        model_id = request.json.get('model', 'gpt-3.5-turbo')
        message_type = request.json.get('type', 'text')  # 添加这行来获取消息类型

        if model_id not in MODELS_CONFIG:
            return jsonify({"error": f"不支持的模型: {model_id}"}), 400

        model_config = MODELS_CONFIG[model_id]
        
        try:
            if model_config.model_type == ModelType.TEXT:
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
                        context_text += "\n历史对话：" + previous_text
                    if user_text.strip():
                        context_text += "\n用户描述：" + user_text

            
                    # 构建带图片的消息
                    current_messages.append({
                        "role": "user",
                        "content": [
                            {"type": "text", "text": context_text},
                            *image_content
                        ]
                    })
                else:
                    # 处理普通文本消息
                    current_messages.append({
                        "role": "user",
                        "content": user_message
                    })
                
                params = model_config.params.copy()
                if 'max_output_tokens' in params:
                    params['max_tokens'] = params.pop('max_output_tokens')
                
                response = model_processor.process_text(
                    messages=current_messages,
                    model_id=model_id,
                    **params
                )
                
                current_messages.append({"role": "assistant", "content": response["content"]})
                chat_session.messages = current_messages
                chat_session.last_message = user_message  # 更新最后一条消息
                chat_session.last_updated = datetime.utcnow()
                db.session.commit()
                
                return jsonify({
                    "response": response,
                    "current_tokens": num_tokens_from_messages(current_messages),
                    "max_tokens": MAX_CONTEXT_LENGTH
                })
            
            elif model_config.model_type == ModelType.IMAGE:
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
                
                    return jsonify({
                        "response": response
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
                    "content": f"处理失败: {str(e)}",
                    "status": "error"
                }
            }), 500
            
    except Exception as e:
        logger.error(f"Chat error for user {current_user.chat_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": f"服务器错误: {str(e)}"}), 500

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
        user = User(username=data.get('username'))
        user.set_password(data.get('password'))
        
        chat_history = ChatHistory(
            user_id=user.chat_id,
            messages=[SYSTEM_MESSAGE]
        )
        
        db.session.add(user)
        db.session.add(chat_history)
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

if __name__ == '__main__':
    with app.app_context():
        # 只在首次运行时创建表
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000) 