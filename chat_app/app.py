from flask import Flask, render_template, request, jsonify, session
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
app.secret_key = 'your-fixed-secret-key'  # 在生产环境中应使用环境变量

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
MAX_TOKENS = 128000  # GPT-4
# MAX_TOKENS = 16000  # GPT-3.5-turbo

# 修改系统消息的内容
SYSTEM_MESSAGE = {
    "role": "system",
    "content": """你是一个有记忆力的AI助手。你需要：
1. 记住当前用户之前说过的所有信息
2. 在回答时要参考当前用户之前的对话内容
3. 如果用户问你之前说过的内容，你要能够准确回忆并回答
4. 保持对话的连贯性和上下文关联
5. 聊天只基于当前用户的历史信息，不要提供其他用户的历史信息
请在每次回答时都查看历史消息，确保回答的连贯性。"""
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
        if len(messages) > 1:
            messages.pop(1)  # 删除系统消息后的最早消息
        else:
            break
    return messages

class ChatHistory(db.Model):
    """聊天历史记录模型"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), nullable=False, unique=True)
    messages = db.Column(db.JSON, nullable=False, default=lambda: [SYSTEM_MESSAGE])
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

@app.before_request
def before_request():
    """请求预处理：检查会话是否过期"""
    if request.endpoint in ['static', 'check_session', 'create_id', 'switch_id']:
        return
    
    if 'user_id' not in session:
        return jsonify({"error": "请先创建或切换到有效的用户ID"}), 401

@app.route('/')
def home():
    """主页路由"""
    return render_template('chat.html')

@app.route('/chat', methods=['POST'])
def chat():
    """处理聊天请求"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            user_id = str(uuid.uuid4())
            session['user_id'] = user_id
            
        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        if not chat_history:
            chat_history = ChatHistory(
                user_id=user_id,
                messages=[SYSTEM_MESSAGE]
            )
            db.session.add(chat_history)
            db.session.commit()
        
        # 获取完整的消息历史
        messages = list(chat_history.messages) if isinstance(chat_history.messages, list) else [SYSTEM_MESSAGE]
        logger.debug(f"Current messages before adding user message: {messages}")
            
        user_message = request.json.get('message', '')
        messages.append({"role": "user", "content": user_message})
        
        # 确保不超过token限制
        messages = trim_messages(messages, MAX_TOKENS - 4000)
        
        logger.debug(f"Messages being sent to OpenAI: {messages}")
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=4000,
            temperature=0.7
        )
        
        assistant_message = response.choices[0].message.content
        messages.append({"role": "assistant", "content": assistant_message})
        
        # 保存更新后的消息历史
        chat_history.messages = messages
        chat_history.last_updated = datetime.utcnow()
        db.session.commit()
        
        current_tokens = num_tokens_from_messages(messages)
        logger.debug(f"Current tokens: {current_tokens}")
        
        return jsonify({
            "response": assistant_message,
            "current_tokens": current_tokens,
            "max_tokens": MAX_TOKENS
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in chat endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"服务器错误: {str(e)}"}), 500

@app.route('/clear_chat', methods=['POST'])
def clear_chat():
    """清除聊天历史"""
    user_id = session.get('user_id')
    chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
    if chat_history:
        chat_history.messages = [SYSTEM_MESSAGE]  # 使用新的系统消息
        chat_history.last_updated = datetime.utcnow()
        db.session.commit()
    return jsonify({"status": "success"})

@app.route('/get_chat_history')
def get_chat_history():
    """获取聊天历史"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"error": "Session expired"}), 401

        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        if not chat_history:
            return jsonify({"error": "Chat history not found"}), 404

        current_tokens = num_tokens_from_messages(chat_history.messages)
        
        return jsonify({
            "messages": chat_history.messages,
            "current_tokens": current_tokens,
            "max_tokens": MAX_TOKENS,
            "user_id": user_id
        })

    except Exception as e:
        logger.error(f"Error getting chat history: {str(e)}")
        return jsonify({"error": f"服务器错误: {str(e)}"}), 500

@app.route('/check_session')
def check_session():
    """检查当前会话状态"""
    user_id = session.get('user_id')
    return jsonify({"user_id": user_id})

@app.route('/create_id', methods=['POST'])
def create_id():
    """创建新的用户ID"""
    new_user_id = str(uuid.uuid4())
    session['user_id'] = new_user_id
    
    # 创建新的聊天历史
    chat_history = ChatHistory(
        user_id=new_user_id,
        messages=[SYSTEM_MESSAGE]
    )
    try:
        db.session.add(chat_history)
        db.session.commit()
        return jsonify({"user_id": new_user_id})
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
        
    # 检查ID是否存在
    chat_history = ChatHistory.query.filter_by(user_id=new_id).first()
    if not chat_history:
        return jsonify({"error": "ID不存在"}), 404
        
    session['user_id'] = new_id
    return jsonify({"user_id": new_id})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000) 