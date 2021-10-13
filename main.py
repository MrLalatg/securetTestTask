from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from tinydb import TinyDB, Query
from typing import List

SECRET_KEY = "e5dca1c38b84bba8de78eea35bc87f19a5043034abea710d731b63d1e841fd90"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 30

db = TinyDB("./db.json")
users = db.table('users')
posts = db.table('posts')
comments = db.table('comments')


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class Credentials(BaseModel):
    username: str
    password: str


class User(BaseModel):
    username: str
    karma: int
    password_hash: str
    posts: List[int]
    comments: List[int]
    rated_posts: List[int]
    rated_comments: List[int]


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def get_user(username: str):
    user = users.search(Query().username == username)  # returns a list, so we'll need to choose later
    if user:
        user_dict = user[0]
        return User(**user_dict)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not pwd_context.verify(password, user.password_hash):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username=username)
    # if user is None:
    #     raise credentials_exception
    # Thought it would be better to still return None without exception to handle it correctly
    return user


@app.post("/register")
async def register(credentials: Credentials):
    if not users.search(Query().username == credentials.username):
        hashed_pwd = pwd_context.hash(credentials.password)
        users.insert({"username": credentials.username,
                      "password_hash": hashed_pwd,
                      "karma": 0,
                      "posts": [],
                      "comments": [],
                      "rated_posts": [],
                      "rated_comments": []
                      })
    return status.HTTP_200_OK


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/post")
async def post(post_header: str, post_text: str, user: User = Depends(get_current_user)):
    if not user:
        return status.HTTP_401_UNAUTHORIZED
    post_id = posts.insert({"header": post_header,
                            "text": post_text,
                            "author": user.username,
                            "karma": 0,
                            "deleted": False})
    posts.update({"post_id": post_id}, doc_ids=[post_id])  # This is a little bit weird, but that's the only thing that can be done with tinyDB
    users.update({"posts": user.posts + [post_id]}, Query().username == user.username)
    return {"post_id": post_id}


@app.post("/comment")
async def comment(parent_id: int, comment_text: str, tree_comment: bool = False, user: User = Depends(get_current_user)):
    if not user:
        return status.HTTP_401_UNAUTHORIZED
    comment_id = comments.insert({"parent_id": parent_id,
                                  "text": comment_text,
                                  "tree_comment": tree_comment,
                                  "author": user.username,
                                  "karma": 0,
                                  "deleted": False})
    comments.update({"comment_id": comment_id}, doc_ids=[comment_id])
    users.update({"comments": user.comments + [comment_id]}, Query().username == user.username)
    return {"comment_id": comment_id}


@app.post("/edit")
async def edit(entity_id: int, new_text: str = None, new_header: str = None, post_flag: bool = True, user: User = Depends(get_current_user)):
    if not user:
        return status.HTTP_401_UNAUTHORIZED

    if post_flag:
        entity = posts.get(doc_id=entity_id)
        if user.username != entity["author"]:
            return status.HTTP_403_FORBIDDEN
        if new_header:
            posts.update({"header": new_header})
        if new_text:
            posts.update({"text": new_text})
    else:
        entity = comments.get(doc_id=entity_id)
        if user.username != entity["author"]:
            return status.HTTP_403_FORBIDDEN
        if new_text:
            comments.update({"text": new_text})


@app.post("/delete")
async def delete(entity_id: int, post_flag: bool = True, user: User = Depends(get_current_user)):
    # I thought it would be better to not delete the whole tree of posts->comment->comment_to_comment
    # but instead mark the post or comment or post as deleted to render it something like "this post was removed"
    # on front-end

    if not user:
        return status.HTTP_401_UNAUTHORIZED
    if post_flag:
        entity = posts.get(doc_id=entity_id)
        if user.username != entity["author"]:
            return status.HTTP_403_FORBIDDEN
        posts.update({"deleted": True, "header": "deleted", "text": "deleted"}, doc_ids=[entity_id])
    else:
        entity = comments.get(doc_id=entity_id)
        if user.username != entity["author"]:
            return status.HTTP_403_FORBIDDEN
        comments.update({"deleted": True, "text": "deleted"}, doc_ids=[entity_id])


@app.get("/allposts")
async def get_posts(limit: int = None):
    all_posts = posts.all()
    if limit:
        result = []
        for i in range(0, limit):
            result.append(all_posts[i])
        return result
    return all_posts


@app.get("/users/{username}")
async def get_user_info(username: str):
    user = users.get(Query().username == username)
    del user["password_hash"]
    return user


@app.get("/entitycomments")
async def get_comments(entity_id: int, post_flag: bool = True):
    # I thought that it would be better to fetch comments "layer by layer" not all at once, so you can load them
    # in front-end on demand (not all tree at once), cuz' otherwise it would not be optimal
    if post_flag:
        comments_list = comments.search((Query().parent_id == entity_id) & (Query().tree_comment == False))
        return comments_list
    else:
        comments_list = comments.search((Query().parent_id == entity_id) & (Query().tree_comment == True))
        return comments_list


@app.post("/rateentity")
async def rating(entity_id: int, rating_change: int = 1, post_flag: bool = True, user: User = Depends(get_current_user)):
    # Included a little feature like Reddit's karma
    if not user:
        return status.HTTP_401_UNAUTHORIZED
    if post_flag:
        if entity_id in user.rated_posts:
            return {"error": "You already rated this post"}
        post = posts.get(doc_id=entity_id)
        posts.update({"karma": post["karma"] + rating_change}, doc_ids=[entity_id])
        author = users.search(Query().username == post["author"])[0]
        users.update({"karma": author["karma"] + rating_change}, Query().username == post["author"])
        users.update({"rated_posts": user.rated_posts + [entity_id]}, Query().username == user.username)
    else:
        if entity_id in user.rated_comments:
            return {"error": "You already rated this comment"}
        curr_comment = comments.get(doc_id=entity_id)
        comments.update({"karma": curr_comment["karma"] + rating_change}, doc_ids=[entity_id])
        author = users.search(Query().username == curr_comment["author"])[0]
        users.update({"karma": author["karma"] + rating_change}, Query().username == curr_comment["author"])
        users.update({"rated_comments": user.rated_comments + [entity_id]}, Query().username == user.username)
