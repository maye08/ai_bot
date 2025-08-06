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
    email = db.Column(db.String(120), unique=True, nullable=False)  # 新增email字段
    password_hash = db.Column(db.String(128))
    chat_id = db.Column(db.String(36), unique=True, nullable=False)
    # is_admin = db.Column(db.Boolean, default=False)  # 添加管理员标志
    email_verified = db.Column(db.Boolean, default=False)  # 添加此字段
    email_verify_token = db.Column(db.String(100))  # 存储验证令牌
    token_expiry = db.Column(db.DateTime)  # 令牌过期时间
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, username, email, email_verified=False, email_verify_token=None, token_expiry=None):
        self.username = username
        self.email = email  # 初始化email
        self.chat_id = str(uuid.uuid4())
        self.email_verified = email_verified
        self.email_verify_token = email_verify_token
        self.token_expiry = token_expiry

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

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.chat_id'), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    plan_type = db.Column(db.String(50), nullable=False)  # 订阅类型
    points = db.Column(db.Integer, default=0)  # 剩余积分
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='active')  # active, expired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_active(self):
        return self.status == 'active' and self.end_date > datetime.utcnow()

class PaymentRecord(db.Model):
    """支付记录"""
    __tablename__ = 'payment_records'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.chat_id'), nullable=False)
    order_id = db.Column(db.String(64), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, success, failed
    payment_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    plan_type = db.Column(db.String(32), nullable=False)

    user = db.relationship('User', backref=db.backref('payments', lazy=True))
    def __init__(self, **kwargs):
        super(PaymentRecord, self).__init__(**kwargs)
