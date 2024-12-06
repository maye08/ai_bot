from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property
import uuid
import logging

# 配置logger
logger = logging.getLogger(__name__)
# 创建数据库实例
db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    chat_id = db.Column(db.String(36), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, username):
        self.username = username
        self.chat_id = str(uuid.uuid4())
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ChatHistory(db.Model):
    __tablename__ = 'chat_histories'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True, nullable=False)
    messages = db.Column(db.JSON, nullable=False, default=list)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, user_id, messages=None):
        self.user_id = user_id
        self.messages = messages or []
        self.last_updated = datetime.utcnow()

class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), nullable=False)
    messages = db.Column(db.JSON, default=list)  # 确保使用JSON类型
    _messages = db.Column('messages', db.JSON, nullable=False, default=list)
    last_message = db.Column(db.String(255))  # 存储最后一条用户消息
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    def __init__(self, user_id, messages=None):
        self.user_id = user_id
        self._messages = messages or []
        self.last_updated = datetime.utcnow()

    @hybrid_property
    def messages(self):
        return self._messages or []
    
    @messages.setter
    def messages(self, value):
        if not isinstance(value, list):
            logger.warning(f"Attempting to set non-list messages: {value}")
            value = []
        logger.debug(f"Setting messages to: {value}")
        self._messages = value.copy()  # 使用copy()避免引用问题