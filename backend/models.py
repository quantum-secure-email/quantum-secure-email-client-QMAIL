from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String)
    picture = Column(String)
    google_id = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    oauth_tokens = relationship("OAuthToken", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    created_groups = relationship("Group", back_populates="creator", cascade="all, delete-orphan")
    group_memberships = relationship("GroupMember", back_populates="user", cascade="all, delete-orphan")
    group_keys = relationship("GroupKey", back_populates="user", cascade="all, delete-orphan")


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text)
    expires_at = Column(DateTime, nullable=False)
    scope = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="oauth_tokens")


class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_id = Column(String, unique=True, nullable=False, index=True)
    pubkey_b64 = Column(Text, nullable=False)
    algo = Column(String, default="Kyber512")
    meta = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="devices")


class Group(Base):
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = relationship("User", back_populates="created_groups")
    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")
    group_keys = relationship("GroupKey", back_populates="group", cascade="all, delete-orphan")


class GroupMember(Base):
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    joined_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('group_id', 'user_id', name='_group_user_uc'),)
    
    # Relationships
    group = relationship("Group", back_populates="members")
    user = relationship("User", back_populates="group_memberships")


class GroupKey(Base):
    __tablename__ = "group_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_group_key = Column(Text, nullable=False)  # AES key encrypted with user's Kyber public key
    algorithm = Column(String, default="Kyber512+AES256")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('group_id', 'user_id', name='_group_key_user_uc'),)
    
    # Relationships
    group = relationship("Group", back_populates="group_keys")
    user = relationship("User", back_populates="group_keys")


class KMStore(Base):
    __tablename__ = "km_store"
    
    id = Column(Integer, primary_key=True, index=True)
    key_id = Column(String, unique=True, nullable=False, index=True)
    key_b64 = Column(Text, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    origin = Column(String, default="sim-qkd")
    meta = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
