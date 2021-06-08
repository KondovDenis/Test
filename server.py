import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
import hmac 
import hashlib
import base64

app = FastAPI()
SECRET_KEY = "b7a166cf1b6da8c2d4c2e80902c915c54a1a604f661372e256cf60d4a1fbc765"
PASSWORD_SALT ='a27406578f7b0bbadb199eea9681bd1356fdbe381be1531725fb7467ed4e9da5'


def sign(data: str) -> str:
    return hmac.new(SECRET_KEY.encode(), msg=data.encode(), digestmod=hashlib.sha256).hexdigest().upper()

def get_username_from_sign(username_signed: str) -> Optional[str]:
    username_base64, hash = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign(username)
    if hmac.compare_digest(valid_sign, hash):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash        




users = {
    'lex@gmail.com':{
       'name' : 'Алексей',
       'balance': 100_000,
       'password': 'c1ea3c8132e94db5f66ef7c15cce4cfef634e1aa5b0bda5a3950e2c516c76c64'
    }
}


@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page=f.read()    
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_sign(username)
    if not valid_username:
        response =  Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user=users[valid_username]
    except KeyError: 
        repsonse = Response(login_page, media_type='text/html')
        repsonse.delete_cookie(key='username')
        return repsonse   
    return Response(
        f'Привет,{users[valid_username]["name"]}!<br />'
        f'Баланс: {users[valid_username]["balance"]}'
    , media_type='text/html')    

    



@app.post('/login')
def process_login_page(username:Optional[str] = Form(None), password:Optional[str] = Form(None)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                'success': False,
                'message': 'Неверный логин или пароль.'
            }),
             media_type='application/json')
    
    response = Response(
            json.dumps({
                'success': True,
                'message': f'Добро пожаловать,{user["name"]} , Ваш баланс:{user["balance"]}'

    }), 
      media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + '.' + \
        sign(username)      
    response.set_cookie(key='username', value=username_signed)
    return response



