from LoginManager import LoginManager


lm = LoginManager()
login_info = lm.login(username="****", password="****")

if login_info != None and login_info["online"] == True:
    print("login success")
