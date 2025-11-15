import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document
from schemas import User as UserSchema, Project as ProjectSchema, ProjectMember, Task as TaskSchema, Subtask as SubtaskSchema, Note as NoteSchema, Role

# Settings
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "public/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Project Camp Backend API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# serve uploads
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Utilities
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenPayload(BaseModel):
    sub: str
    exp: int
    type: str

class CurrentUser(BaseModel):
    id: str
    email: EmailStr
    name: str
    role: Role
    is_email_verified: bool

# Helper functions

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(user_id: str, token_type: str, expires_delta: timedelta) -> str:
    to_encode = {
        "sub": user_id,
        "type": token_type,
        "exp": datetime.now(timezone.utc) + expires_delta,
    }
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email})


def get_user_by_id(user_id: str) -> Optional[dict]:
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> CurrentUser:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if authorization.lower().startswith("bearer "):
        token = authorization.split()[1]
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization header")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user = get_user_by_id(payload.get("sub"))
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return CurrentUser(
            id=str(user["_id"]),
            email=user["email"],
            name=user.get("name", ""),
            role=user.get("role", "member"),
            is_email_verified=user.get("is_email_verified", False),
        )
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# RBAC helpers

def require_roles(*allowed_roles: Role):
    async def _dep(user: CurrentUser = Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return _dep


def require_project_role(min_roles: List[Role]):
    async def _dep(project_id: str, user: CurrentUser = Depends(get_current_user)):
        proj = db["project"].find_one({"_id": ObjectId(project_id)})
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        if user.role == "admin":
            return user
        # find membership
        member = next((m for m in proj.get("members", []) if m.get("user_id") == user.id), None)
        if not member:
            raise HTTPException(status_code=403, detail="Not a project member")
        if member.get("role") not in min_roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return _dep


# Email sending stub (prints to logs)

def send_email(to: str, subject: str, body: str):
    print(f"[Email] To: {to} | Subject: {subject} | Body: {body}")


# Auth Routes
class RegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    new_password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/api/v1/auth/register")
def register(payload: RegisterRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    verification_token = create_token("pending", "verify", timedelta(hours=24))
    hashed = hash_password(payload.password)
    user = UserSchema(
        email=payload.email,
        name=payload.name,
        password_hash=hashed,
        role="member",
        is_email_verified=False,
        email_verification_token=verification_token,
    )
    uid = create_document("user", user)
    send_email(payload.email, "Verify your email", f"Click to verify: /api/v1/auth/verify-email/{verification_token}")
    return {"id": uid, "message": "Registered. Please verify your email."}


@app.get("/api/v1/auth/verify-email/{verification_token}")
def verify_email(verification_token: str):
    try:
        payload = jwt.decode(verification_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "verify":
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    # find user with this token
    user = db["user"].find_one({"email_verification_token": verification_token})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"is_email_verified": True}, "$unset": {"email_verification_token": ""}})
    return {"message": "Email verified"}


@app.post("/api/v1/auth/login", response_model=Token)
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.get("is_email_verified", False):
        raise HTTPException(status_code=403, detail="Email not verified")
    access = create_token(str(user["_id"]), "access", timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh = create_token(str(user["_id"]), "refresh", timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return Token(access_token=access, refresh_token=refresh)


@app.post("/api/v1/auth/logout")
def logout(_: CurrentUser = Depends(get_current_user)):
    # Stateless JWT: client discards tokens. For real blacklist, store token identifiers.
    return {"message": "Logged out"}


@app.post("/api/v1/auth/refresh-token", response_model=Token)
def refresh_token(payload: RefreshRequest):
    try:
        decoded = jwt.decode(payload.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid token type")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    user_id = decoded.get("sub")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    access = create_token(user_id, "access", timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh = create_token(user_id, "refresh", timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return Token(access_token=access, refresh_token=refresh)


@app.get("/api/v1/auth/current-user")
def current_user(user: CurrentUser = Depends(get_current_user)):
    return user


@app.post("/api/v1/auth/change-password")
def change_password(payload: ChangePasswordRequest, user: CurrentUser = Depends(get_current_user)):
    db_user = get_user_by_id(user.id)
    if not verify_password(payload.current_password, db_user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    db["user"].update_one({"_id": db_user["_id"]}, {"$set": {"password_hash": hash_password(payload.new_password)}})
    return {"message": "Password changed"}


@app.post("/api/v1/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    user = get_user_by_email(payload.email)
    if not user:
        return {"message": "If the account exists, an email has been sent"}
    token = create_token(str(user["_id"]), "reset", timedelta(hours=1))
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"reset_password_token": token, "reset_password_expires_at": datetime.now(timezone.utc) + timedelta(hours=1)}})
    send_email(user["email"], "Reset Password", f"Reset link: /api/v1/auth/reset-password/{token}")
    return {"message": "If the account exists, an email has been sent"}


@app.post("/api/v1/auth/reset-password/{reset_token}")
def reset_password(reset_token: str, payload: ResetPasswordRequest):
    try:
        decoded = jwt.decode(reset_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded.get("type") != "reset":
            raise HTTPException(status_code=400, detail="Invalid token type")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = db["user"].find_one({"reset_password_token": reset_token})
    if not user:
        raise HTTPException(status_code=404, detail="Invalid or expired token")
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": hash_password(payload.new_password)}, "$unset": {"reset_password_token": "", "reset_password_expires_at": ""}})
    return {"message": "Password reset successful"}


class ResendVerificationRequest(BaseModel):
    email: EmailStr

@app.post("/api/v1/auth/resend-email-verification")
def resend_email_verification(payload: ResendVerificationRequest):
    user = get_user_by_email(payload.email)
    if not user:
        return {"message": "If the account exists, an email has been sent"}
    if user.get("is_email_verified", False):
        return {"message": "Email already verified"}
    token = create_token("pending", "verify", timedelta(hours=24))
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"email_verification_token": token}})
    send_email(payload.email, "Verify your email", f"Click to verify: /api/v1/auth/verify-email/{token}")
    return {"message": "Verification email resent"}


# Healthcheck
@app.get("/api/v1/healthcheck/")
def healthcheck():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


# Project Routes
class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class MemberUpdate(BaseModel):
    user_id: str
    role: Role

@app.get("/api/v1/projects/")
def list_projects(user: CurrentUser = Depends(get_current_user)):
    # Admin: list all; else list projects where user is owner or member
    q = {} if user.role == "admin" else {"$or": [{"owner_id": user.id}, {"members.user_id": user.id}]}
    projects = list(db["project"].find(q))
    for p in projects:
        p["id"] = str(p.pop("_id"))
    return projects


@app.post("/api/v1/projects/")
def create_project(payload: ProjectCreate, user: CurrentUser = Depends(require_roles("admin"))):
    proj = ProjectSchema(name=payload.name, description=payload.description, owner_id=user.id, members=[ProjectMember(user_id=user.id, role="project_admin")])
    pid = create_document("project", proj)
    return {"id": pid}


@app.get("/api/v1/projects/{project_id}")
def get_project(project_id: str, user: CurrentUser = Depends(get_current_user)):
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    # visibility: member or admin
    if user.role != "admin" and user.id not in [proj.get("owner_id")] + [m.get("user_id") for m in proj.get("members", [])]:
        raise HTTPException(status_code=403, detail="Forbidden")
    proj["id"] = str(proj.pop("_id"))
    return proj


@app.put("/api/v1/projects/{project_id}")
def update_project(project_id: str, payload: ProjectUpdate, user: CurrentUser = Depends(require_roles("admin"))):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["project"].update_one({"_id": ObjectId(project_id)}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"message": "Updated"}


@app.delete("/api/v1/projects/{project_id}")
def delete_project(project_id: str, user: CurrentUser = Depends(require_roles("admin"))):
    res = db["project"].delete_one({"_id": ObjectId(project_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    # cascade delete tasks, subtasks, notes
    task_ids = [str(t["_id"]) for t in db["task"].find({"project_id": project_id})]
    db["task"].delete_many({"project_id": project_id})
    if task_ids:
        db["subtask"].delete_many({"task_id": {"$in": task_ids}})
    db["note"].delete_many({"project_id": project_id})
    return {"message": "Deleted"}


# Members management
@app.get("/api/v1/projects/{project_id}/members")
def list_members(project_id: str, user: CurrentUser = Depends(get_current_user)):
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if user.role != "admin" and user.id not in [proj.get("owner_id")] + [m.get("user_id") for m in proj.get("members", [])]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return proj.get("members", [])


@app.post("/api/v1/projects/{project_id}/members")
def add_member(project_id: str, payload: MemberUpdate, user: CurrentUser = Depends(require_roles("admin"))):
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    members = proj.get("members", [])
    if any(m.get("user_id") == payload.user_id for m in members):
        raise HTTPException(status_code=400, detail="User already a member")
    members.append({"user_id": payload.user_id, "role": payload.role})
    db["project"].update_one({"_id": proj["_id"]}, {"$set": {"members": members}})
    return {"message": "Member added"}


@app.put("/api/v1/projects/{project_id}/members")
def update_member_role(project_id: str, payload: MemberUpdate, user: CurrentUser = Depends(require_roles("admin"))):
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    members = proj.get("members", [])
    found = False
    for m in members:
        if m.get("user_id") == payload.user_id:
            m["role"] = payload.role
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail="Member not found")
    db["project"].update_one({"_id": proj["_id"]}, {"$set": {"members": members}})
    return {"message": "Member role updated"}


@app.delete("/api/v1/projects/{project_id}/members/{member_user_id}")
def remove_member(project_id: str, member_user_id: str, user: CurrentUser = Depends(require_roles("admin"))):
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    members = [m for m in proj.get("members", []) if m.get("user_id") != member_user_id]
    db["project"].update_one({"_id": proj["_id"]}, {"$set": {"members": members}})
    return {"message": "Member removed"}


# Task Routes
class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    assignee_id: Optional[str] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    status: Optional[str] = None

class SubtaskCreate(BaseModel):
    details: str

class SubtaskUpdate(BaseModel):
    details: Optional[str] = None
    completed: Optional[bool] = None

@app.get("/api/v1/tasks/{project_id}")
def list_tasks(user: CurrentUser = Depends(require_project_role(["member", "project_admin"])) , project_id: str = None):
    tasks = list(db["task"].find({"project_id": project_id}))
    for t in tasks:
        t["id"] = str(t.pop("_id"))
    return tasks


@app.post("/api/v1/tasks/{project_id}")
def create_task(payload: TaskCreate, user: CurrentUser = Depends(require_project_role(["project_admin"])) , project_id: str = None):
    # Only admin or project_admin
    task = TaskSchema(project_id=project_id, title=payload.title, description=payload.description, assignee_id=payload.assignee_id)
    tid = create_document("task", task)
    return {"id": tid}


@app.get("/api/v1/tasks/{project_id}/t/{task_id}")
def get_task(task_id: str, user: CurrentUser = Depends(require_project_role(["member", "project_admin"])) , project_id: str = None):
    t = db["task"].find_one({"_id": ObjectId(task_id), "project_id": project_id})
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    t["id"] = str(t.pop("_id"))
    return t


@app.put("/api/v1/tasks/{project_id}/t/{task_id}")
def update_task(task_id: str, payload: TaskUpdate, user: CurrentUser = Depends(require_project_role(["project_admin"])) , project_id: str = None):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["task"].update_one({"_id": ObjectId(task_id), "project_id": project_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Updated"}


@app.delete("/api/v1/tasks/{project_id}/t/{task_id}")
def delete_task(task_id: str, user: CurrentUser = Depends(require_project_role(["project_admin"])) , project_id: str = None):
    res = db["task"].delete_one({"_id": ObjectId(task_id), "project_id": project_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    db["subtask"].delete_many({"task_id": task_id})
    return {"message": "Deleted"}


# Attachments upload
@app.post("/api/v1/tasks/{project_id}/t/{task_id}/attachments")
async def upload_attachment(task_id: str, file: UploadFile = File(...), user: CurrentUser = Depends(require_project_role(["project_admin"])) , project_id: str = None):
    # save file
    file_path = os.path.join(UPLOAD_DIR, f"{datetime.now().timestamp()}_{file.filename}")
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)
    url = f"/uploads/{os.path.basename(file_path)}"
    mime = file.content_type or "application/octet-stream"
    size = len(contents)
    db["task"].update_one({"_id": ObjectId(task_id), "project_id": project_id}, {"$push": {"attachments": {"url": url, "mime_type": mime, "size": size}}})
    return {"url": url, "mime_type": mime, "size": size}


# Subtasks
@app.post("/api/v1/tasks/{project_id}/t/{task_id}/subtasks")
def create_subtask(task_id: str, payload: SubtaskCreate, user: CurrentUser = Depends(require_project_role(["project_admin"])) , project_id: str = None):
    # Only admin/project_admin
    # Ensure task exists
    t = db["task"].find_one({"_id": ObjectId(task_id), "project_id": project_id})
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    st = SubtaskSchema(task_id=task_id, details=payload.details)
    sid = create_document("subtask", st)
    return {"id": sid}


@app.put("/api/v1/tasks/{project_id}/st/{subtask_id}")
def update_subtask(subtask_id: str, payload: SubtaskUpdate, user: CurrentUser = Depends(require_project_role(["member", "project_admin"])) , project_id: str = None):
    # Members can update completion status and details
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    # ensure subtask belongs to project
    st = db["subtask"].find_one({"_id": ObjectId(subtask_id)})
    if not st:
        raise HTTPException(status_code=404, detail="Subtask not found")
    t = db["task"].find_one({"_id": ObjectId(st.get("task_id")), "project_id": project_id})
    if not t:
        raise HTTPException(status_code=404, detail="Task not found for project")
    db["subtask"].update_one({"_id": ObjectId(subtask_id)}, {"$set": update})
    return {"message": "Updated"}


@app.delete("/api/v1/tasks/{project_id}/st/{subtask_id}")
def delete_subtask(subtask_id: str, user: CurrentUser = Depends(require_project_role(["project_admin"])) , project_id: str = None):
    st = db["subtask"].find_one({"_id": ObjectId(subtask_id)})
    if not st:
        raise HTTPException(status_code=404, detail="Subtask not found")
    t = db["task"].find_one({"_id": ObjectId(st.get("task_id")), "project_id": project_id})
    if not t:
        raise HTTPException(status_code=404, detail="Task not found for project")
    db["subtask"].delete_one({"_id": ObjectId(subtask_id)})
    return {"message": "Deleted"}


# Notes
class NoteCreate(BaseModel):
    content: str

class NoteUpdate(BaseModel):
    content: Optional[str] = None

@app.get("/api/v1/notes/{project_id}")
def list_notes(user: CurrentUser = Depends(require_project_role(["member", "project_admin"])) , project_id: str = None):
    notes = list(db["note"].find({"project_id": project_id}))
    for n in notes:
        n["id"] = str(n.pop("_id"))
    return notes


@app.post("/api/v1/notes/{project_id}")
def create_note(payload: NoteCreate, user: CurrentUser = Depends(require_roles("admin")) , project_id: str = None):
    # Admin only per PRD
    # Ensure user can see project for safety
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    note = NoteSchema(project_id=project_id, content=payload.content)
    nid = create_document("note", note)
    return {"id": nid}


@app.get("/api/v1/notes/{project_id}/n/{note_id}")
def get_note(note_id: str, user: CurrentUser = Depends(require_project_role(["member", "project_admin"])) , project_id: str = None):
    n = db["note"].find_one({"_id": ObjectId(note_id), "project_id": project_id})
    if not n:
        raise HTTPException(status_code=404, detail="Note not found")
    n["id"] = str(n.pop("_id"))
    return n


@app.put("/api/v1/notes/{project_id}/n/{note_id}")
def update_note(note_id: str, payload: NoteUpdate, user: CurrentUser = Depends(require_roles("admin")) , project_id: str = None):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["note"].update_one({"_id": ObjectId(note_id), "project_id": project_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    return {"message": "Updated"}


@app.delete("/api/v1/notes/{project_id}/n/{note_id}")
def delete_note(note_id: str, user: CurrentUser = Depends(require_roles("admin")) , project_id: str = None):
    res = db["note"].delete_one({"_id": ObjectId(note_id), "project_id": project_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    return {"message": "Deleted"}


# Root and test
@app.get("/")
def read_root():
    return {"message": "Project Camp Backend API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
