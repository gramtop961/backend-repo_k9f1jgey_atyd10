"""
Database Schemas for Project Camp Backend

Collections are inferred from Pydantic model class names (lowercased):
- User -> "user"
- Project -> "project"
- Task -> "task"
- Subtask -> "subtask"
- Note -> "note"

These are used both for validation and to guide DB operations.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# Auth and Users
Role = Literal["admin", "project_admin", "member"]

class User(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=120)
    password_hash: str
    role: Role = "member"
    is_email_verified: bool = False
    email_verification_token: Optional[str] = None
    reset_password_token: Optional[str] = None
    reset_password_expires_at: Optional[datetime] = None

# Projects and Memberships
class ProjectMember(BaseModel):
    user_id: str
    role: Role = "member"

class Project(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    owner_id: str
    members: List[ProjectMember] = []

# Tasks, Subtasks, Attachments
TaskStatus = Literal["todo", "in_progress", "done"]

class Attachment(BaseModel):
    url: str
    mime_type: str
    size: int = Field(..., ge=0)

class Task(BaseModel):
    project_id: str
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=5000)
    assignee_id: Optional[str] = None
    status: TaskStatus = "todo"
    attachments: List[Attachment] = []

class Subtask(BaseModel):
    task_id: str
    details: str = Field(..., min_length=1, max_length=2000)
    completed: bool = False

# Notes
class Note(BaseModel):
    project_id: str
    content: str = Field(..., min_length=1, max_length=10000)
