from flask import Flask, render_template, request, jsonify, session, redirect
from openai import OpenAI
import tiktoken
import os
import logging
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import traceback
import json

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 会话配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)
app.secret_key = 'your-fixed-secret-key'  # 请在生产环境中使用安全的密钥

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True, nullable=False)  # 确保user_id是唯一的
    messages = db.Column(db.JSON, nullable=False, default=list)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, user_id, messages=None, last_updated=None):
        self.user_id = user_id
        self.messages = messages or [SYSTEM_MESSAGE]
        self.last_updated = last_updated or datetime.utcnow()

@app.before_request
def before_request():
    """请求预处理：检查会话是否过期"""
    if request.endpoint in ['static', 'create_id', 'switch_id', 'default_home', 'user_chat', 'get_chat_history']:  # 添加 get_chat_history
        return
    
    if 'user_id' not in session:
        return jsonify({"error": "请先创建或切换到有效的用户ID"}), 401

@app.route('/')
def default_home():
    """默认主页，重定向到新用户ID"""
    new_id = str(uuid.uuid4())
    return redirect(f'/{new_id}')

@app.route('/<user_id>')
def user_chat(user_id):
    """特定用户的聊天页面"""
    return render_template('chat.html', user_id=user_id)

@app.route('/create_id', methods=['POST'])
def create_id():
    """创建新的用户ID"""
    try:
        new_id = str(uuid.uuid4())
        chat_history = ChatHistory(
            user_id=new_id,
            messages=[SYSTEM_MESSAGE]
        )
        db.session.add(chat_history)
        db.session.commit()
        
        return jsonify({
            "user_id": new_id,
            "redirect_url": f"/{new_id}"
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating chat history: {str(e)}")
        return jsonify({"error": "创建聊天历史失败"}), 500

@app.route('/switch_id', methods=['POST'])
def switch_id():
    """切换到已有的用户ID"""
    new_id = request.json.get('user_id')
    if not new_id:
        return jsonify({"error": "未提供用户ID"}), 400
        
    chat_history = ChatHistory.query.filter_by(user_id=new_id).first()
    if not chat_history:
        return jsonify({"error": "ID不存在"}), 404
        
    session['user_id'] = new_id
    return jsonify({
        "user_id": new_id,
        "redirect_url": f"/{new_id}"
    })

@app.route('/get_chat_history')
def get_chat_history():
    """获取聊天历史"""
    try:
        user_id = request.args.get('user_id')  # 使用URL参数中的user_id
        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400

        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        if not chat_history:
            return jsonify({"error": "Chat history not found"}), 404

        messages = chat_history.messages if isinstance(chat_history.messages, list) else [SYSTEM_MESSAGE]
        current_tokens = num_tokens_from_messages(messages)
        
        logger.debug(f"Fetching chat history for user {user_id}, found {len(messages)} messages")
        
        return jsonify({
            "messages": messages,
            "current_tokens": current_tokens,
            "max_tokens": MAX_TOKENS,
            "user_id": user_id
        })

    except Exception as e:
        logger.error(f"Error getting chat history: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": f"获取聊天历史失败: {str(e)}"}), 500

@app.route('/chat', methods=['POST'])
def chat():
    """处理聊天请求"""
    try:
        user_id = request.json.get('user_id')  # 从请求中获取user_id
        if not user_id:
            return jsonify({"error": "Missing user_id"}), 400
            
        # 确保为当前用户获取正确的聊天历史
        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        if not chat_history:
            # 为新用户创建聊天历史
            chat_history = ChatHistory(
                user_id=user_id,
                messages=[SYSTEM_MESSAGE],
                last_updated=datetime.utcnow()
            )
            db.session.add(chat_history)
            db.session.commit()
        
        # 获取用户消息
        user_message = request.json.get('message', '')
        
        # 构建当前用户的消息列表
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
        logger.error(f"Chat error for user {user_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": f"服务器错误: {str(e)}"}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000) 