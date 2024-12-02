from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from openai import OpenAI
import tiktoken
import os
import logging
from datetime import datetime, timedelta
import uuid
import traceback
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, ChatHistory
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import random
import string
import base64

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
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

# 设置 token 限制
MAX_TOKENS = 64000

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

def trim_messages(messages, max_tokens):
    """保留系统消息和最近的对话"""
    while messages and num_tokens_from_messages(messages) > max_tokens:
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
            "max_tokens": MAX_TOKENS
        })
        
    except Exception as e:
        logger.error(f"Error getting chat history: {str(e)}")
        return jsonify({"error": "获取聊天历史失败"}), 500

@app.route('/chat', methods=['POST'])
@login_required
def chat_message():
    """处理聊天请求"""
    try:
        # 使用当前用户的chat_id
        chat_history = ChatHistory.query.filter_by(user_id=current_user.chat_id).first()
        if not chat_history:
            return jsonify({"error": "聊天历史不存在"}), 404
            
        user_message = request.json.get('message', '')
        
        # 构建当前户的消息列表
        current_messages = []
        if isinstance(chat_history.messages, list):
            current_messages = chat_history.messages.copy()
        else:
            current_messages = [SYSTEM_MESSAGE]
        
        # 添加当前用户消息
        current_messages.append({"role": "user", "content": user_message})
        
        # 确保不超过token限制
        if num_tokens_from_messages(current_messages) > MAX_TOKENS - 1000:
            current_messages = [SYSTEM_MESSAGE] + current_messages
        
        # 发送请求到OpenAI
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=current_messages,
            max_tokens=1000,
            temperature=0.7
        )
        
        assistant_message = response.choices[0].message.content
        
        # 更新当前用户的历史记录
        current_messages.append({"role": "assistant", "content": assistant_message})
        chat_history.messages = current_messages
        chat_history.last_updated = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "response": assistant_message,
            "current_tokens": num_tokens_from_messages(current_messages),
            "max_tokens": MAX_TOKENS
        })
        
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
            "max_tokens": MAX_TOKENS
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

if __name__ == '__main__':
    with app.app_context():
        # 只在首次运行时创建表
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000) 